#!/usr/bin/env python3

import sys
import os
import re
import json
import logging
import datetime
import subprocess

from collections import defaultdict

from http import cookiejar
from urllib import request
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.error import HTTPError

from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler


class HTTPRequestHandler(BaseHTTPRequestHandler):

    demo = True
    timeout = 30
    centers = None
    cookies = cookiejar.CookieJar()

    def do_GET(self):

        _, _, path, query, _ = urlsplit(self.path)
        params = parse_qs(query)

        logging.info("do_GET: path=%s, params=%s", path, params)

        if path == "/":
            return self.get_home_page()

        if path == "/login":
            return self.send_html_page("login")

        if path == "/login-tfa":
            self.send_tfa_request()
            return self.send_html_page("login-tfa")

        if path == "/logout":
            return self.do_logout()

        if path == "/gateway-status":
            return self.get_gateway_status()

        if path == "/user-info":
            return self.get_user_info()

        if path == "/vaccination-centers":
            return self.get_vaccination_centers()

        if path == "/vaccination-center-timeslots":
            return self.get_vaccination_center_timeslots(params)

        self.send_error(404, "do_GET: %s not supported!", self.path)

    def do_POST(self):
        logging.debug("POST %s", self.path)
        content_length = int(self.headers['Content-Length'])
        data = parse_qs(self.rfile.read(content_length).decode("utf-8"))
        logging.info("POST %s: %s", self.path, data)

        if self.path == "/login":
            return self.do_login(data)

        if self.path == "/login-tfa":
            return self.do_login_tfa(data)

        if self.path == "/appointment":
            return self.do_appointment(data)

        self.send_error(404, "POST {} not supported!".format(self.path))

    def is_demo(self):
        return self.__class__.demo

    def set_demo(self, value):
        logging.info("demo mode: %s", value)
        if not value:
            self.__class__.centers = None
        self.__class__.demo = value

    def read_html(self, name):
        return open(os.path.join("pages", "{}.html".format(name)), mode='rb').read()

    def send_html(self, html):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html)

    def send_html_page(self, name):
        self.send_html(self.read_html(name))

    def send_json(self, obj):
        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=UTF-8")
        self.end_headers()
        self.wfile.write(
            json.dumps(obj, ensure_ascii=False, indent=3).encode("utf-8")
        )

    def read_demo_json(self, name):
        return json.load(open(os.path.join("demo", "{}.json".format(name))))

    def send_redirect(self, url, code=302):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def get_home_page(self):
        html = self.read_html("index")
        if self.is_demo():
            html = html.replace(b"GESY Vaccination", b"GESY Vaccination (DEMO)")
            html = html.replace(b"Logout", b"Login")
            html = html.replace(b"/logout", b"/login")
        return self.send_html(html)

    def send_tfa_request(self):
        text = self.make_text_request("https://vaccination.gesy.org.cy/api/tfa/request", data=b"{}")
        logging.info("send_tfa_request: %s", text)

    def do_login(self, data):
        self.make_request("https://vaccination.gesy.org.cy")

        self.make_request(
            "https://oam.gesy.org.cy/oam/server/auth_cred_submit",
            data=urlencode(dict(username=data["username"][0], password=data["password"][0])).encode("utf-8")
        )

        tfa_status = self.make_text_request("https://vaccination.gesy.org.cy/api/tfa/status")

        if "2FA_PROMPT" in tfa_status:
            self.set_demo(False)
            return self.send_redirect("/login-tfa")

        logging.warning("unknown tfa response: %s", tfa_status)
        self.send_redirect("/login")

    def do_login_tfa(self, data):

        code = data["code"][0]
        text = self.make_text_request("https://vaccination.gesy.org.cy/api/tfa/validate?otp={}".format(code), data=b"{}")
        logging.info("tfa validate: %s", text)

        if "2FA_OTP_VALID" in text:
            return self.send_redirect("/")

        return self.send_redirect("/login-tfa")

    def do_logout(self):
        self.make_request(
            "https://vaccination.gesy.org.cy/logout?end_url=https://vaccination.gesy.org.cy/"
        )
        self.set_demo(True)
        self.send_redirect("/")

    def do_appointment(self, data):

        params = {
            "name":        data["name"][0],
            "surname":     data["surname"][0],
            "dob":         data["dob"][0],
            "idDocType":   data["idDocType"][0],
            "idNumber":    data["idNumber"][0],
            "phonenumber": data["phonenumber"][0],
            "email":       data["email"][0],
            "vcCenter":    data["vcCenter"][0],
            "vcDate":      data["vcDate"][0],
            "vcTime":      data["vcDate"][0].split("T")[1]
        }

        logging.info("do_appointment: sending request: %s", params)

        if self.is_demo():
            text = "DEMO Mode, not submitted"
        else:
            text = self.make_text_request(
                "https://vaccination.gesy.org.cy/vscy/vaccination/insertnewbeneficiaryappointment",
                data=urlencode(params).encode("utf-8")
            )

        logging.info("do_appointment: response: %s", text)

        self.send_json(dict(response=text))

    def get_demo_status(self):
        self.send_json(self.demo)

    def get_gateway_status(self):
        if self.is_demo():
            status = self.read_demo_json("gateway_status")
        else:
            status = self.make_json_request("https://vaccination.gesy.org.cy/vscy/vaccination/hiogatewayavailability")
        if status is None:
            logging.error("get_gateway_status: cannot make request")
            return
        logging.info("get_gateway_status: %s", status)
        self.send_json(status)

    def get_user_info(self):
        if self.is_demo():
            user_info = self.read_demo_json("user_info")
            user_profile = self.read_demo_json("user_profile")
        else:
            user = self.make_json_request("https://vaccination.gesy.org.cy/api/user/benctxt")
            if user is None:
                logging.error("get_user_info: cannot get user")
                return
            user_info = self.make_json_request(
                "https://vaccination.gesy.org.cy/api/beneficiaries/info",
                headers={"X-act-for": user["benId"]}
            )
            user_profile = self.make_json_request("https://vaccination.gesy.org.cy/api/user/profile")
        if user_info is None:
            logging.error("get_user_info: cannot get user_info")
            return
        if user_profile is None:
            logging.error("get_user_info: cannot get user_info")
            return

        for k in ["mobile", "email"]:
            user_info[k] = user_profile[k]

        logging.info("get_user_info: %s", user_info)
        self.send_json(user_info)

    def get_vaccination_centers(self):
        if self.__class__.centers:
            return self.send_json(self.__class__.centers)

        if self.is_demo():
            centers = self.read_demo_json("getcentersallocations")
        else:
            centers = self.make_json_request("https://vaccination.gesy.org.cy/vscy/vaccination/getcentersallocations")

        centers["dict"] = {}
        for center in centers["allocations"]:
            centers["dict"][center["centerCd"]] = center
            center["type-by-days"], center["default-type"] = self.parse_vaccine_type(center["type"])
        self.__class__.centers = centers

        self.send_json(centers)

    @staticmethod
    def parse_vaccine_type(text):

        if "(" not in text:
            return dict(), text

        composite_vaccine_type = re.compile(r"([^(]+[(][^)]+[)])[ /]*")
        composite_vaccine_dates = re.compile(r"([0-9,]+/[0-9]+/2021),?")

        vaccine_type_by_days = dict()
        vaccine_type_default = "Unknown"

        for vaccine_title in composite_vaccine_type.findall(text):
            vaccine_name = vaccine_title.split("(")[0]
            for vaccine_dates in composite_vaccine_dates.findall(vaccine_title):
                days, month, year = vaccine_dates.split("/")
                for day in days.split(","):
                    date = "{0}-{1:0>2s}-{2:0>2s}".format(year, month, day)
                    vaccine_type_by_days[date] = vaccine_name

        return vaccine_type_by_days, vaccine_type_default

    def get_vaccination_center_timeslots(self, params):
        center = params["center"][0]
        centers = self.__class__.centers
        if self.is_demo():
            data = self.read_demo_json("gettwoweekslotsbycenter-{}".format(center))
        else:
            data = self.make_json_request(
                "https://vaccination.gesy.org.cy/vscy/Vaccination/gettwoweekslotsbycenter?vcId={}".format(center),
                data=b"{}"
            )

        timeslots = []
        for slot in data:
            day = slot["vcStartDate"].split("T")[0]
            timeslots.append(dict(
                id="{}@{}".format(slot["vcStartDate"].rsplit(":", 1)[0], slot["vcId"]),
                time=slot["vcStartTime"],
                datetime=slot["vcStartDate"],
                centerName=centers["dict"][center]["center"],
                typeTitle=centers["dict"][center]["type"],
                type=centers["dict"][center]["type-by-days"].get(day, centers["dict"][center]["default-type"])
            ))

        self.send_json(timeslots)

    def dump_files(self):

        logging.info("dump_files")
        centers = self.make_json_request("https://vaccination.gesy.org.cy/vscy/vaccination/getcentersallocations")
        with open("dump/getcentersallocations.json", "w", encoding='utf-8') as f:
            json.dump(centers, fp=f, ensure_ascii=False, indent=3)

        for center in centers["allocations"]:
            centerCd=center["centerCd"]
            logging.info(centerCd)
            timeslots = self.make_json_request(
                "https://vaccination.gesy.org.cy/vscy/Vaccination/gettwoweekslotsbycenter?vcId={}".format(centerCd),
                data=b"{}"
            )
            with open("dump/gettwoweekslotsbycenter-{}".format(centerCd), "w", encoding='utf-8') as f:
                json.dump(timeslots, fp=f, ensure_ascii=False, indent=3)

    def make_request(self, url, data=None, headers=None):
        headers_list = [
            ("Accept-Language", "en"),
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15"),
        ]
        logging.info("make_request: %s", url)
        opener = request.build_opener(
            request.HTTPCookieProcessor(self.__class__.cookies)
        )
        if headers is not None:
            headers_list.extend(list(headers.items()))
        opener.addheaders = headers_list
        try:
            res = opener.open(url, data, self.timeout)
        except HTTPError as e:
            logging.error(e)
            return

        logging.debug("make_request: status=%d, content-type=%s", res.status, res.info().get_content_type())

        return res

    def make_text_request(self, url, data=None, headers=None):
        res = self.make_request(url, data, headers)
        return res.read().decode("utf-8")

    def make_json_request(self, url, data=None, headers=None):
        res = self.make_request(url, data, headers)
        content_type = res.info().get_content_type()
        text = res.read().decode("utf-8")
        if content_type != "application/json":
            logging.error("make_json_request: wrong content type: %s", content_type)
            logging.error("make_json_request: text: '%s'", text)
            return None
        return json.loads(text)


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass


def open_browser(url):

    if sys.platform == "win32":
        os.startfile(url)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", url])
    else:
        try:
            subprocess.Popen(["xdg-open", url])
        except OSError:
            print("Please open a browser on: %s".format(url))


if __name__ == "__main__":

    logging.basicConfig(format='%(asctime)s %(threadName)s %(levelname)s %(message)s', level=logging.DEBUG)

    server = ThreadingSimpleServer(("127.0.0.1", 8080), HTTPRequestHandler)

    open_browser("http://127.0.0.1:8080")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server")
