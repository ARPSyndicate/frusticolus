#!/usr/bin/python3

from aiohttp_socks import ProxyConnector
from backoff import on_exception, expo
from collections import defaultdict
from configparser import ConfigParser
from datetime import datetime
from multiprocessing import active_children
from multiprocessing import Process
from nltk.corpus import words
from os_urlpattern.formatter import pformat
from os_urlpattern.pattern_maker import PatternMaker
from os_urlpattern.pattern_matcher import PatternMatcher
from PIL import Image, ImageFilter, ImageEnhance, ImageFile
from pyvirtualdisplay import Display
from Screenshot import Screenshot
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from tqdm import tqdm
from urllib.parse import urlsplit, unquote, urlparse
import aiohttp
import asyncio
import codecs
import concurrent.futures
import cv2
import easyocr
import hashlib
import json
import lxml.html
import nltk
import numpy as np
import optparse
import os
import puncia
import re
import seleniumwire.undetected_chromedriver as uc
import socket
import sqlite3
import sys
import time
import tldextract

BLUE = "\033[94m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CLEAR = "\x1b[0m"

start_time = time.time()

ImageFile.LOAD_TRUNCATED_IMAGES = True


tqdm.write(BLUE + "Falco(F.)rusticolus [v1.1]" + CLEAR)
tqdm.write(BLUE + "A.R.P. Syndicate [https://www.arpsyndicate.io]" + CLEAR)
tqdm.write(YELLOW + "An Intelligent URL Profiler" + CLEAR)


parser = optparse.OptionParser()
parser.add_option(
    "-c",
    "--config",
    action="store",
    dest="config",
    help="path to frusticolus.ini",
    default="frusticolus.ini",
)

inputs, args = parser.parse_args()

if not os.path.exists(inputs.config):
    parser.error(RED + "[!] invalid path to frusticolus.ini" + CLEAR)

config = ConfigParser()
with open(inputs.config) as f:
    config.read_file(f, inputs.config)


input_path = config.get("paths", "input")
output_path = config.get("paths", "output")
whitelist_path = config.get("paths", "whitelist")
blacklist_path = config.get("paths", "blacklist")
fingerprints_path = config.get("paths", "fingerprints")
mode = config.get("vars", "mode").lower()
eshot = config.get("vars", "screenshot").lower()
ocr = config.get("vars", "ocr").lower() == "true"
headless = config.get("vars", "headless").lower() == "true"
crawl = config.get("vars", "crawl").lower() == "true"
replica = config.get("vars", "replica").lower() == "true"
vulns = config.get("vars", "vulns").lower() == "true"
proxy = config.get("vars", "proxy")
tor = config.get("vars", "tor").lower() == "true"
if tor:
    proxy = "socks5h://127.0.0.1:9050"
    os.system("sudo service tor start")
timeout = max(100, int(config.get("vars", "timeout")))
retries = int(config.get("vars", "retries"))
browsers = int(config.get("vars", "concurrency"))
hashes = {}
metadata = {}
captcha = []
targets = []
whitelist_patterns = []
blacklist_patterns = []
fingerprints = {}
raw_data = {}
etdoms = set()

tmpdir = output_path + ".tmp"
conn = sqlite3.connect(output_path)


def load_words():
    nltk_words = set(words.words())
    return nltk_words


def save_raw_data(driver):
    global raw_data
    for request in driver.requests:
        if request.response:
            raw_data[request.url] = {
                "method": request.method,
                "request_headers": request.headers,
                "response_status_code": request.response.status_code,
                "response_headers": request.response.headers,
                "response_body": request.response.body.decode("utf-8", errors="ignore"),
            }


def ocr_analysis(image_path):
    global fingerprints
    reader = easyocr.Reader(["en"])
    image = cv2.imread(image_path)
    result = reader.readtext(image)
    areas = []
    for bbox, text, prob in result:
        points = np.array(bbox, dtype=np.int32)
        x1, y1 = points[0]
        x2, y2 = points[2]
        area = (x2 - x1) * (y2 - y1)
        areas.append((area, text, bbox))
    areas_sorted = sorted(areas, reverse=True, key=lambda x: x[0])
    result = [
        re.sub(r"[^a-zA-Z0-9\s]", "-", areas_sorted[0][1].lower().replace(" ", "-"))
    ]
    for tech in fingerprints:
        if any(
            " " + tech.lower() + " "
            in " " + re.sub(r"[^a-zA-Z0-9\s]", " ", stre[1].lower()) + " "
            for stre in areas_sorted
        ):
            result.append(tech.lower())
    result = list(set(result))
    return result


def get_null_urls(col, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    union_query = " UNION ALL ".join(
        [
            f'SELECT url FROM "{table_name[0]}" WHERE {col} IS NULL OR {col} = ""'
            for table_name in tables
            if table_name[0] != "raw_data"
        ]
    )
    results = []
    if union_query:
        cursor.execute(union_query)
        urls_with_empty_status = cursor.fetchall()
        for (url,) in urls_with_empty_status:
            results.append(url)
    return results


def url_filter(
    urls, idom="", threads=3, characters=100, multiplierx=2, replacer="frusticolus"
):

    pattern_maker = PatternMaker()
    pattern_matcher = PatternMatcher()
    media_extensions = (
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".pdf",
        ".mp4",
        ".mp3",
        ".wav",
        ".avi",
        ".mov",
        ".zip",
    )

    def cleanup(urls):
        nurls = []
        for item in urls:
            if len(item) <= characters and not item.lower().endswith(media_extensions):
                try:
                    nurls.append(unquote(item.strip("&/= ")))
                except:
                    nurls.append(item.strip("&/= "))
        urls = nurls
        nurls = []
        for url in urls:
            try:
                extracted = tldextract.extract(url)
            except:
                continue
            rdom = "{0}.{1}".format(extracted.domain, extracted.suffix)
            if len(extracted.subdomain) > 0:
                rdom = "{0}.{1}".format(extracted.subdomain, rdom)
            if len(idom) > 0:
                if rdom.endswith("." + idom) or rdom == idom:
                    nurls.append(url)
            else:
                nurls.append(url)
        urls = list(set(nurls))
        domains = []
        parsed_urls = {}
        for url in urls:
            parsed = urlparse(url)
            params = []
            for param in parsed.query.split("&"):
                params.append(param.split("=")[0])
            domains.append(parsed.scheme + "://" + parsed.netloc)
            if parsed.scheme + "://" + parsed.netloc + parsed.path in list(
                parsed_urls.keys()
            ):
                parsed_urls[parsed.scheme + "://" + parsed.netloc + parsed.path].extend(
                    params
                )
            else:
                parsed_urls[parsed.scheme + "://" + parsed.netloc + parsed.path] = (
                    params
                )
            parsed_urls[parsed.scheme + "://" + parsed.netloc + parsed.path] = list(
                set(parsed_urls[parsed.scheme + "://" + parsed.netloc + parsed.path])
            )
            parsed_urls[parsed.scheme + "://" + parsed.netloc + parsed.path].sort()

        domains = list(set(domains))
        newurls = []
        for url in parsed_urls:
            parsed_urls[url] = list(filter(None, parsed_urls[url]))
            if len(parsed_urls[url]) > 0:
                paramstr = ("=" + replacer + "&").join(parsed_urls[url]) + (
                    "=" + replacer
                )
                newurls.append(url + "?" + paramstr)
            else:
                newurls.append(url)

        avgurl = (int(len(newurls) / max(1, len(domains)))) * multiplierx
        parsed_urls = {}
        for url in newurls:
            parsed = urlparse(url)
            params = []
            domains.append(parsed.scheme + "://" + parsed.netloc)
            if parsed.scheme + "://" + parsed.netloc in list(parsed_urls.keys()):
                parsed_urls[parsed.scheme + "://" + parsed.netloc].append(
                    parsed.path + "?" + parsed.query
                )
            else:
                parsed_urls[parsed.scheme + "://" + parsed.netloc] = [
                    parsed.path + "?" + parsed.query
                ]

        yclu = []
        for url in parsed_urls:
            if len(parsed_urls[url]) > avgurl:
                yclu.append(url)

        ncluster = []
        ycluster = []
        for url in newurls:
            brk = False
            for i in yclu:
                if i in url:
                    ycluster.append(url)
                    brk = True
                    break
            if not brk:
                ncluster.append(url)
        return ncluster, ycluster

    def genp(url):
        global iunm
        try:
            pattern_maker.load(url)
        except:
            iunm.append(url)

    def match_all(url):
        global mdata, iunm
        try:
            matched_results = pattern_matcher.match(url)
            patterns = sorted(matched_results, reverse=True)[0].meta
            try:
                mdata[patterns].append(url)
            except:
                mdata[patterns] = [url]
        except:
            xunm.append(url)

    ncluster, ycluster = cleanup(urls)

    urls = ycluster
    result = []
    durls = {}
    lsurls = len(urls)
    for url in urls:
        try:
            extracted = tldextract.extract(url)
        except Exception as ex:
            exc = "[{0}] {1}".format(str(ex.__class__.__name__), url)
            continue
        rdom = "{0}.{1}".format(extracted.domain, extracted.suffix)
        if len(extracted.subdomain) > 0:
            rdom = "{0}.{1}".format(extracted.subdomain, rdom)
            if rdom in list(durls.keys()):
                durls[rdom].append(url)
            else:
                durls[rdom] = [url]
        else:
            if rdom in list(durls.keys()):
                durls[rdom].append(url)
            else:
                durls[rdom] = [url]

    for ukey in list(durls.keys()):
        urls = durls[ukey]
        iunm = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            try:
                executor.map(genp, urls)
            except (KeyboardInterrupt, SystemExit):
                executor.shutdown(wait=False)
                sys.exit()
        iunm = list(set(iunm))
        iunm.sort()
        for url in iunm:
            urls.remove(url)
        enumex = []
        for url_meta, clustered in pattern_maker.make():
            for pattern in pformat("pattern", url_meta, clustered):
                enumex.append(pattern)
        for i in range(0, len(enumex)):
            try:
                pattern_matcher.load(enumex[i], meta=i)
            except:
                continue
        mdata = {}
        xunm = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            try:
                executor.map(match_all, urls)
            except (KeyboardInterrupt, SystemExit):
                executor.shutdown(wait=False)
                sys.exit()
        xunm = list(set(xunm))
        xunm.sort()
        for kdi in mdata.keys():
            for data in mdata[kdi]:
                result.append("[{0}] {1}".format(ukey + enumex[kdi], data))
        eunm = []
        inumex = []
        for i in range(0, len(enumex)):
            if i not in mdata.keys():
                inumex.append(enumex[i])
        inumex = sorted(inumex, key=len, reverse=True)

        def match_rem(d):
            global eunm, inumex, result
            for i in inumex:
                parsed = urlsplit(url)
                z = re.search(i, d.replace(parsed.scheme + "://" + parsed.netloc, ""))
                if z:
                    eunm.append(d)
                    result.append("[{0}] {1}".format(ukey + i, d))
                    break

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            try:
                executor.map(match_rem, xunm)
            except (KeyboardInterrupt, SystemExit):
                executor.shutdown(wait=False)
                sys.exit()
        eunm = list(set(eunm))
        for e in eunm:
            xunm.remove(e)
        iunm = iunm + xunm
        for data in iunm:
            if data[0] == ":":
                data = data.replace("://", "")
            result.append("[UNCLUSTERED] {0}".format(data))

    for url in ncluster:
        if url[0] == ":":
            url = url.replace("://", "")
        result.append("[UNCLUSTERED] {0}".format(url))

    result.sort()
    fresult = ""
    fresult = ("%s" % line for line in result)

    uda = ""
    diout = {}

    for line in fresult:
        try:
            kout = line.split(" ")[0]
            dout = line.split(" ")[1]
            if kout in diout:
                diout[kout].append(dout)
            else:
                diout[kout] = [dout]
        except:
            continue

    for i in diout:
        if i != "[UNCLUSTERED]":
            uda = uda + diout[i][0] + "\n"
        else:
            uda = uda + "\n".join(diout[i])
            uda = uda + "\n"
    return uda.split("\n")


def create_rawdata_table(conn):
    with conn:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS "raw_data" (
                url TEXT PRIMARY KEY NOT NULL,
                method TEXT,
                request_headers TEXT,
                response_status_code INTEGER,
                response_headers TEXT,
                response_body TEXT,
                timestamp TEXT
            );
        """
        )


def create_domain_table(domain_name, conn):
    with conn:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS "{domain_name}" (
                url TEXT PRIMARY KEY NOT NULL,
                subdomain TEXT,
                screenshot BLOB,
                status_code INTEGER,
                title TEXT,
                content_length INTEGER,
                content_md5sum TEXT,
                captcha_protection TEXT,
                cookies TEXT,
                content TEXT,
                tags TEXT,
                fingerprints TEXT,
                vulns TEXT,
                timestamp TEXT
            );
        """
        )


def insert_data(
    conn,
    domain_name,
    url,
    subdomain,
    screenshot_path="",
    status_code="",
    title="",
    content_length="",
    content_md5sum="",
    captcha=False,
    cookies={},
    content="",
    tags=[],
    fingerprints=[],
    vulns=[],
    force=False,
):
    screenshot_blob = ""
    if len(screenshot_path) > 0:
        with open(screenshot_path, "rb") as file:
            screenshot_blob = file.read()
    cookies_json = json.dumps(cookies)
    if force:
        query = "INSERT OR REPLACE INTO"
    else:
        query = "INSERT OR IGNORE INTO"
    with conn:
        try:
            conn.execute(
                f"""
                {query} "{domain_name}"
                (url, subdomain, screenshot, status_code, title, content_length, content_md5sum, captcha_protection, cookies, content, tags, fingerprints, vulns, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    url,
                    subdomain,
                    screenshot_blob,
                    status_code,
                    title,
                    content_length,
                    content_md5sum,
                    captcha,
                    cookies_json,
                    content,
                    ",".join(tags),
                    ",".join(fingerprints),
                    ",".join(vulns),
                    str(datetime.now()),
                ),
            )
        except:
            pass


def insert_rawdata(
    conn,
    url,
    method="",
    request_headers=[],
    response_status_code="",
    response_headers=[],
    response_body="",
):
    request_headers_json = json.dumps(request_headers)
    response_headers_json = json.dumps(response_headers)
    query = "INSERT OR REPLACE INTO"
    with conn:
        try:
            conn.execute(
                f"""
                {query} "raw_data"
                (url, method, request_headers, response_status_code, response_headers, response_body, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    url,
                    method,
                    request_headers_json,
                    response_status_code,
                    response_headers_json,
                    response_body,
                    str(datetime.now()),
                ),
            )
        except:
            pass


def make_entries(url):
    global conn, metadata
    create_domain_table(metadata[url]["domain"], conn)
    insert_data(
        conn,
        metadata[url]["domain"],
        url,
        metadata[url]["subdomain"],
        metadata[url]["screenshot"],
        metadata[url]["status_code"],
        metadata[url]["title"],
        metadata[url]["content_length"],
        metadata[url]["content_md5sum"],
        metadata[url]["captcha"],
        metadata[url]["cookies"],
        metadata[url]["content"],
        metadata[url]["tags"],
        metadata[url]["fingerprints"],
        metadata[url]["vulns"],
        force=True,
    )


def getMD5(dta):
    try:
        dta = codecs.encode(dta, "base64")
        return hashlib.md5(dta).hexdigest()
    except:
        return None


def check_captcha(source):
    return (
        "Verify you are human" in source
        or "Enable JavaScript and cookies to continue" in source
    )


def fetch_vulns(keyword):
    json_data = puncia.query_api("exploit", keyword)
    if isinstance(json_data, dict):
        aliases = json_data["aliases"]
        return aliases
    return []


async def resolve_subdomain(subdomain):
    try:
        await asyncio.get_running_loop().getaddrinfo(subdomain, None)
        return True
    except socket.gaierror:
        return False


async def is_live(url, session):
    global timeout
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                return True
    except Exception:
        pass
    return False


async def check_subdomains(domain):
    global proxy, timeout, replica
    subdomains = puncia.query_api("subdomain", domain)
    if replica:
        replicas = puncia.query_api("replica", domain)
        subdomains.extend(replicas)
    live_subdomains = []
    try:
        session_timeout = aiohttp.ClientTimeout(sock_connect=timeout, sock_read=timeout)
        if len(proxy) > 0 and (
            "http://" in proxy or "socks5h://" in proxy or "socks5://" in proxy
        ):
            connc = ProxyConnector.from_url(
                proxy.replace("socks5h://", "socks5://"), ssl=False, limit=browsers * 2
            )
        async with aiohttp.ClientSession(
            timeout=session_timeout, connector=connc
        ) as session:
            resolved_subdomains = [
                subdomain
                for subdomain, resolved in zip(
                    subdomains,
                    await asyncio.gather(*[resolve_subdomain(s) for s in subdomains]),
                )
                if resolved
            ]
            probe_tasks = []
            for subdomain in resolved_subdomains:
                http_url = f"http://{subdomain}"
                https_url = f"https://{subdomain}"
                probe_tasks.append(is_live(http_url, session))
                probe_tasks.append(is_live(https_url, session))
            probe_results = await asyncio.gather(*probe_tasks)
            for i in range(len(resolved_subdomains)):
                if probe_results[i * 2] or probe_results[i * 2 + 1]:
                    live_subdomains.append(f"http://{resolved_subdomains[i]}")
                    live_subdomains.append(f"https://{resolved_subdomains[i]}")
    except:
        pass
    return live_subdomains


@on_exception(expo, Exception, max_tries=retries)
async def hashSRC(session, url):
    global hashes, pbar, exceptr, metadata, captcha, etdoms
    try:
        async with session.get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"
            },
            allow_redirects=True,
        ) as response:
            html = await response.text()
            hashed = getMD5(html)
            if hashed in list(hashes.keys()):
                hashes[hashed].append(url)
            else:
                hashes[hashed] = [url]
            capt = check_captcha(str(html))
            if capt:
                captcha.append(url)
            extracted = tldextract.extract(url)
            metadata[url] = {
                "domain": f"{extracted.domain}.{extracted.suffix}".strip("."),
                "subdomain": f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".strip(
                    "."
                ),
                "status_code": response.status,
                "content_length": len(html),
                "content_md5sum": hashed,
                "captcha": capt,
                "screenshot": "",
                "title": "",
                "cookies": [],
                "content": html,
                "tags": [],
                "fingerprints": [],
                "vulns": [],
            }
            etdoms.add(metadata[url]["domain"])
            pbar.update(1)
    except Exception as ex:
        exc = "[{0}] {1}".format(str(ex.__class__.__name__), url)
        if exc not in exceptr:
            exceptr.append(exc)
            tqdm.write(RED + exc + CLEAR)
        raise


async def gather_with_concurrency(n, *coros):
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(sem_coro(c) for c in coros), return_exceptions=True)


async def findSRCs(urls):
    global timeout, browsers, proxy
    session_timeout = aiohttp.ClientTimeout(sock_connect=timeout, sock_read=timeout)
    connc = aiohttp.TCPConnector(ssl=False, limit=browsers * 2)
    if len(proxy) > 0 and (
        "http://" in proxy or "socks5h://" in proxy or "socks5://" in proxy
    ):
        connc = ProxyConnector.from_url(
            proxy.replace("socks5h://", "socks5://"), ssl=False, limit=browsers * 2
        )
    async with aiohttp.ClientSession(
        timeout=session_timeout, connector=connc
    ) as session:
        tasks = []
        for tart in urls:
            task = asyncio.ensure_future(hashSRC(session, tart))
            tasks.append(task)
        await gather_with_concurrency(browsers, *tasks)


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def bypass_checks(driver, url, reconnect_time=15):
    driver.execute_script('window.open("%s","_blank");' % url)
    time.sleep(1)
    driver.close()
    driver.reconnect(reconnect_time)
    time.sleep(1)
    driver.switch_to.window(driver.window_handles[-1])


def click_cfturnstile_strategyA(driver):
    time.sleep(5)
    action = ActionChains(driver)
    action.send_keys(Keys.TAB * 1)
    action.send_keys(Keys.SPACE)
    time.sleep(5)


def click_cfturnstile_strategyB(driver, image):
    readscr = cv2.imread(image)
    window_size = driver.execute_script(
        "return [window.innerWidth, window.innerHeight];"
    )
    window_width, window_height = window_size[0], window_size[1]
    screenshot_height, screenshot_width, _ = readscr.shape
    gray_screenshot = cv2.cvtColor(readscr, cv2.COLOR_BGR2GRAY)
    _, processed_image = cv2.threshold(gray_screenshot, 150, 255, cv2.THRESH_BINARY_INV)
    data = pytesseract.image_to_data(
        processed_image, output_type=pytesseract.Output.DICT
    )
    search_text = "human"
    found = False
    for i in reversed(range(len(data["text"]))):
        text = data["text"][i]
        if search_text.lower() in text.lower():
            x, y, w, h = (
                data["left"][i],
                data["top"][i],
                data["width"][i],
                data["height"][i],
            )
            scale_x = window_width / screenshot_width
            scale_y = window_height / screenshot_height
            adjusted_x = int(x * scale_x)
            adjusted_y = int(y * scale_y)
            adjusted_w = int(w * scale_x)
            adjusted_h = int(h * scale_y)
            action = ActionChains(driver)
            action.move_by_offset(
                adjusted_x + adjusted_w // 2, adjusted_y + adjusted_h // 2
            ).click().perform()
            found = True
            time.sleep(10)
            break


async def get_subdomain_urls(alldomains):
    new_urls = []
    for domain in alldomains:
        live_urls = await check_subdomains(domain)
        new_urls.extend(live_urls)
    return new_urls


def browser(tars):
    global retries, pbar, captcha, metadata, mode, tmpdir, eshot, crawls, ocr, crawl, headless, fingerprints, proxy
    if headless:
        display = Display(visible=0, size=(1024, 768))
        display.start()
    options = webdriver.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--start-maximized")
    options.add_argument("--no-first-run --no-service-autorun --password-store=basic")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--window-size=1024,768")
    options.add_argument("--high-dpi-support=1")
    options.add_argument("--force-device-scale-factor=1")
    try:
        if len(proxy) > 0 and (
            "http://" in proxy or "socks5://" in proxy or "socks5h://" in proxy
        ):
            proxy_options = {
                "proxy": {
                    "http": proxy,
                    "https": proxy,
                    "no_proxy": "localhost,127.0.0.1",
                }
            }
            driver = uc.Chrome(
                options=options,
                browser_executable_path="/var/chrome/chrome",
                seleniumwire_options=proxy_options,
                driver_executable_path="/usr/bin/chromedriver",
                version_main=130,
                use_subprocess=True,
            )
        else:
            driver = uc.Chrome(
                options=options,
                browser_executable_path="/var/chrome/chrome",
                driver_executable_path="/usr/bin/chromedriver",
                version_main=130,
                use_subprocess=True,
            )
        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
        driver.execute_cdp_cmd(
            "Page.setDownloadBehavior",
            {"behavior": "deny", "downloadPath": "/dev/null"},
        )
        ss = Screenshot.Screenshot()
    except Exception as ex:
        tqdm.write(RED + "[BROWSER EXCEPTION] - " + str(ex.__class__.__name__) + CLEAR)
        return
    for target in tars:
        for retry in range(0, retries):
            try:
                if target not in captcha:
                    driver.get(target)
                    time.sleep(5)
                    if eshot == "full":
                        image = ss.full_screenshot(
                            driver,
                            save_path=tmpdir,
                            image_name=target.replace(":", "_").replace("/", "_")
                            + ".png",
                        )
                        metadata[target]["screenshot"] = (
                            tmpdir + target.replace(":", "_").replace("/", "_") + ".png"
                        )
                    elif eshot == "main":
                        driver.save_screenshot(
                            tmpdir + target.replace(":", "_").replace("/", "_") + ".png"
                        )
                        metadata[target]["screenshot"] = (
                            tmpdir + target.replace(":", "_").replace("/", "_") + ".png"
                        )
                else:
                    bypass_checks(driver, target, 15)
                    click_cfturnstile_strategyA(driver)
                    if check_captcha(driver.page_source):
                        image = driver.save_screenshot(
                            tmpdir + target.replace(":", "_").replace("/", "_") + ".png"
                        )
                        time.sleep(3)
                        click_cfturnstile_strategyB(
                            driver,
                            tmpdir
                            + target.replace(":", "_").replace("/", "_")
                            + ".png",
                        )
                        time.sleep(3)
                        if eshot == "full":
                            image = ss.full_screenshot(
                                driver,
                                save_path=tmpdir,
                                image_name=target.replace(":", "_").replace("/", "_")
                                + ".png",
                            )
                            metadata[target]["screenshot"] = (
                                tmpdir
                                + target.replace(":", "_").replace("/", "_")
                                + ".png"
                            )
                        elif eshot == "main":
                            driver.save_screenshot(
                                tmpdir
                                + target.replace(":", "_").replace("/", "_")
                                + ".png"
                            )
                            metadata[target]["screenshot"] = (
                                tmpdir
                                + target.replace(":", "_").replace("/", "_")
                                + ".png"
                            )
                metadata[target]["title"] = driver.title
                metadata[target]["cookies"] = driver.get_cookies()
                metadata[target]["content"] = driver.page_source
                if crawl:
                    crawls.extend(
                        lxml.html.fromstring(driver.page_source).xpath("//a/@href")
                    )
                if ocr and (eshot == "full" or eshot == "main"):
                    metadata[target]["tags"] = ocr_analysis(
                        tmpdir + target.replace(":", "_").replace("/", "_") + ".png"
                    )
                for tech in fingerprints:
                    for ment in fingerprints[tech]["metadata"]:
                        if (
                            ment.lower()
                            in json.dumps(metadata[target]["cookies"]).lower()
                        ):
                            metadata[target]["fingerprints"].append(tech)
                            break
                    if (
                        any(
                            re.match(pattern, metadata[target]["content"])
                            for pattern in fingerprints[tech]["source"]
                        )
                        and len(fingerprints[tech]["source"]) > 0
                    ):
                        metadata[target]["fingerprints"].append(tech)
                        continue
                    if tech in ",".join(metadata[target]["tags"]) or tech in metadata[
                        target
                    ]["title"].lower().replace(" ", "-"):
                        metadata[target]["fingerprints"].append(tech)
                        continue
                metadata[target]["fingerprints"] = list(
                    set(metadata[target]["fingerprints"])
                )
                for matches in metadata[target]["fingerprints"]:
                    metadata[target]["vulns"].extend(fetch_vulns(matches))
                if mode == "smart":
                    for hsh in list(hashes.keys()):
                        if target in hashes[hsh]:
                            for tar in hashes[hsh]:
                                metadata[tar]["title"] = metadata[target]["title"]
                                metadata[tar]["cookies"] = metadata[target]["cookies"]
                                metadata[tar]["content"] = metadata[target]["content"]
                                metadata[tar]["screenshot"] = metadata[target][
                                    "screenshot"
                                ]
                                metadata[tar]["tags"] = metadata[target]["tags"]
                                metadata[tar]["fingerprints"] = metadata[target][
                                    "fingerprints"
                                ]
                                metadata[tar]["vulns"] = metadata[target]["vulns"]
                tqdm.write(BLUE + "[+] " + target + CLEAR)
                pbar.update(1)
                break
            except Exception as ex:
                if retry >= retries - 1:
                    exc = "[{0}] {1}".format(str(ex.__class__.__name__), target)
                    tqdm.write(RED + exc + CLEAR)
                continue
    save_raw_data(driver)
    driver.quit()


if not os.path.exists(tmpdir):
    os.makedirs(tmpdir, exist_ok=True)

if os.path.exists(whitelist_path):
    with open(whitelist_path) as f:
        whitelist_patterns = f.read().splitlines()

if os.path.exists(blacklist_path):
    with open(blacklist_path) as f:
        blacklist_patterns = f.read().splitlines()

if os.path.exists(fingerprints_path):
    with open(fingerprints_path) as f:
        fingerprints = json.load(f)

if os.path.exists(input_path):
    with open(input_path) as f:
        targets = f.read().splitlines()


targets.extend(get_null_urls("status_code", conn))
if eshot in ["full", "main"]:
    targets.extend(get_null_urls("screenshot", conn))

if len(whitelist_patterns) > 0:
    targets = [
        target
        for target in targets
        if any(re.match(pattern, target) for pattern in whitelist_patterns)
    ]

if len(blacklist_patterns) > 0:
    targets = [
        target
        for target in targets
        if not any(re.match(pattern, target) for pattern in blacklist_patterns)
    ]


if len(targets) <= 0:
    tqdm.write(RED + "[!] no valid targets" + CLEAR)
    sys.exit(0)

if mode == "smart":
    targets = url_filter(targets)

targets = list(set(targets))
targets = list(filter(None, targets))
ctar = len(targets)
crawls = []
tmpdir = tmpdir.strip("/") + "/"

pbar = tqdm(total=len(targets), desc=YELLOW + "[*] fingerprinting" + CLEAR)
asyncio.get_event_loop().run_until_complete(findSRCs(targets))
pbar.close()
pbar = tqdm(total=len(targets), desc=YELLOW + "[*] profiling" + CLEAR)

if mode == "smart":
    targets = []
    for hsh in list(hashes.keys()):
        if all(item not in captcha for item in hashes[hsh]):
            targets.append(hashes[hsh][0])
        else:
            targets.extend(hashes[hsh])

targets = list(chunks(targets, browsers))

with concurrent.futures.ThreadPoolExecutor(max_workers=browsers) as executor:
    try:
        executor.map(browser, targets)
    except (KeyboardInterrupt, SystemExit):
        tqdm.write(RED + "[!] interrupted" + CLEAR)
        executor.shutdown(wait=False)
        sys.exit()

active = active_children()
for child in active:
    child.kill()
for child in active:
    child.join()
pbar.close()

for target in metadata:
    make_entries(target)

if crawl:
    crawls.extend(asyncio.run(get_subdomain_urls(list(etdoms))))
    if mode == "smart":
        crawls = url_filter(crawls)
    for url in crawls:
        if url.startswith("http://") or url.startswith("https://"):
            extracted = tldextract.extract(url)
            create_domain_table(
                f"{extracted.domain}.{extracted.suffix}".strip("."), conn
            )
            insert_data(
                conn=conn,
                domain_name=f"{extracted.domain}.{extracted.suffix}".strip("."),
                url=url,
                subdomain=f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".strip(
                    "."
                ),
            )

create_rawdata_table(conn)
for rawd in raw_data:
    insert_rawdata(
        conn,
        rawd,
        method=raw_data[rawd]["method"],
        request_headers=dict(raw_data[rawd]["request_headers"]),
        response_status_code=raw_data[rawd]["response_status_code"],
        response_headers=dict(raw_data[rawd]["response_headers"]),
        response_body=raw_data[rawd]["response_body"],
    )


conn.commit()
conn.close()
os.system("rm -r " + tmpdir)
if tor:
    os.system("sudo service tor stop")
tqdm.write(YELLOW + "[*] done" + CLEAR)
duration = time.time() - start_time
tqdm.write(YELLOW + f"[*] processed {ctar} targets in {duration} seconds" + CLEAR)
