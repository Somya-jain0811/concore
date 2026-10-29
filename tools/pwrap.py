#PW
import logging
import os
import time
from ast import literal_eval
import requests

try:
    import concore
except ImportError:
    concore = None

timeout_max = 20


def mask_apikey(key: str) -> str:
    """Return a masked representation of an API key for safe logging.

    Exposes at most the last 4 characters if the key is long enough,
    redacting the sensitive portion with asterisks.
    """
    if not key:
        return "<empty>"
    key_str = str(key).strip()
    if not key_str:
        return "<empty>"
    prefix = ""
    secret = key_str
    if "?apikey=" in key_str:
        prefix, secret = key_str.split("?apikey=", 1)
        prefix += "?apikey="
    elif "apikey=" in key_str:
        prefix, secret = key_str.split("apikey=", 1)
        prefix += "apikey="

    if len(secret) <= 4:
        masked_secret = "****"
    else:
        masked_secret = f"{'*' * (len(secret) - 4)}{secret[-4:]}"
    return f"{prefix}{masked_secret}"


def run():
    global concore
    if concore is None:
        import concore

    concore.delay = 0.02

    try:
        with open(concore.inpath + '1/concore.apikey', newline=None) as f:
            apikey = f.readline().rstrip()
    except (OSError, IOError):
        try:
            # perhaps this should be removed for security
            with open('./concore.apikey', newline=None) as f:
                apikey = f.readline().rstrip()
        except (OSError, IOError):
            apikey = ''

    try:
        with open(concore.inpath + '1/concore.yuyu', newline=None) as f:
            yuyu = f.readline().rstrip()
    except (OSError, IOError):
        try:
            with open('./concore.yuyu', newline=None) as f:
                yuyu = f.readline().rstrip()
        except (OSError, IOError):
            yuyu = 'yuyu'

    try:
        with open(concore.inpath + '1/concore.name1', newline=None) as f:
            name1 = f.readline().rstrip()
    except (OSError, IOError):
        try:
            with open('./concore.name1', newline=None) as f:
                name1 = f.readline().rstrip()
        except (OSError, IOError):
            name1 = 'u'

    try:
        with open(concore.inpath + '1/concore.name2', newline=None) as f:
            name2 = f.readline().rstrip()
    except (OSError, IOError):
        try:
            with open('./concore.name2', newline=None) as f:
                name2 = f.readline().rstrip()
        except (OSError, IOError):
            name2 = 'ym'

    try:
        with open(concore.inpath + '1/concore.init1', newline=None) as f:
            init_simtime_u = f.readline().rstrip()
    except (OSError, IOError):
        try:
            with open('./concore.init1', newline=None) as f:
                init_simtime_u = f.readline().rstrip()
        except (OSError, IOError):
            init_simtime_u = "[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]"

    with open("./" + name1, "w") as fcopy:
        fcopy.write(init_simtime_u)

    try:
        with open(concore.inpath + '1/concore.init2', newline=None) as f:
            init_simtime_ym = f.readline().rstrip()
    except (OSError, IOError):
        try:
            with open('./concore.init2', newline=None) as f:
                init_simtime_ym = f.readline().rstrip()
        except (OSError, IOError):
            init_simtime_ym = "[0.0, 0.0, 0.0]"

    logging.debug(f"API Key: {mask_apikey(apikey)}")
    logging.info(f"Yuyu: {yuyu}")
    logging.info(f"{name1}={init_simtime_u}")
    logging.info(f"{name2}={init_simtime_ym}")

    while not os.path.exists(concore.inpath + '1/' + name2):
        time.sleep(concore.delay)

    concore.default_maxtime(150)

    u = concore.initval(init_simtime_u)
    oldu = init_simtime_u
    oldt = 0

    with open('./' + name1, 'rb') as f1, open(concore.inpath + '1/' + name2, 'rb') as f2:
        initfiles = {'file1': f1, 'file2': f2}
        r = requests.post('https://www.controlcore.org/init/' + yuyu + apikey, files=initfiles)

    while concore.simtime < concore.maxtime:
        logging.debug("PW outer loop")
        while concore.unchanged():
            ym = concore.read(1, name2, init_simtime_ym)
        with open(concore.inpath + '1/' + name2, 'rb') as f:
            logging.debug(f"PW: before post ym={ym}")
            logging.debug(f'https://www.controlcore.org/ctl/{yuyu}{mask_apikey(apikey)}&fetch={name1}')
            r = requests.post(
                'https://www.controlcore.org/ctl/' + yuyu + apikey + '&fetch=' + name1,
                files={'file1': f},
                timeout=timeout_max,
            )
        if r.status_code != 200:
            logging.error(f"bad POST request {r.status_code}")
            quit()
        if len(r.text) != 0:
            try:
                t = literal_eval(r.text)[0]
            except Exception:
                logging.error(f"bad eval {r.text}")
        timeout_count = 0
        t1 = time.perf_counter()
        logging.debug(f"PW: after post status={r.status_code} r.content={r.content}/{r.text}")
        while oldt == t or len(r.content) == 0:
            time.sleep(concore.delay)
            logging.debug(f"PW waiting status={r.status_code} content={r.content.decode('utf-8')} t={t}")
            with open(concore.inpath + '1/' + name2, 'rb') as f:
                try:
                    r = requests.post(
                        'https://www.controlcore.org/ctl/' + yuyu + apikey + '&fetch=' + name1,
                        files={'file1': f},
                        timeout=timeout_max,
                    )
                except Exception:
                    logging.error("PW: bad requests")
            timeout_count += 1
            if r.status_code != 200 or time.perf_counter() - t1 > 1.1 * timeout_max:
                logging.error(f"timeout or bad POST request {r.status_code}")
                quit()
            if len(r.text) != 0:
                try:
                    t = literal_eval(r.text)[0]
                except Exception:
                    logging.error(f"bad eval {r.text}")
        oldt = t
        oldu = r.text
        logging.debug(f"PW: oldu={oldu} t={concore.simtime}")
        concore.write(1, name1, oldu)

    logging.info(f"retry={concore.retrycount}")


if __name__ == "__main__":
    run()
