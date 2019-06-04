import os
from datetime import datetime

import sqlite3
from sqlite3 import Error

from flask import render_template
from flask import request
from flask import Flask

app = Flask(__name__)
from verify import *


@app.route('/', methods=['GET'])
def home():
    """Renders the home page."""

    """
    Preraring Params
    
    1: Get params from URL
    """
    ####---- From URL ----####
    tag_uid = request.args.get('U')
    tag_flag_tamper = request.args.get('TF')
    tag_time_stamp = request.args.get('TS')
    tag_rolling_code = request.args.get('RLC')
    
    try:
        if len(tag_uid) and len(tag_flag_tamper) and len(tag_time_stamp) and len(tag_rolling_code):
            pass
    except:
        title = "SIC43S1: ERROR! - Wrong format params."
        return render_template(
                'index.html',
                title = title,
                uid = 'N/A',
                key = 'N/A',
                flag_tamper = 'N/A',
                flag_tamper_from_server = 'N/A',
                flag_tamper_decision = 'N/A',

                time_stamp_int = 'N/A',
                time_stamp_from_server = 'N/A',
                time_stamp_decision = 'N/A',

                rolling_code = 'N/A',
                rolling_code_from_server = 'N/A',
                rolling_code_decision = 'N/A'
            )

    if len(tag_uid) == 14 and len(tag_flag_tamper) == 2 and len(tag_time_stamp) == 8 and len(tag_rolling_code) == 90:
        """
        Preraring Params
        
        1: Convert flag_tamper to hex eg. '00'=='3030','AA'=='4141'
        2: Check SIC43S1 RLC param, 
            if RLC length == 32 maybe CMAC alg.
            else if RLC length == 80 maybe OCB alg.
        """
        tag_uid = tag_uid.upper()
        tag_flag_tamper = tag_flag_tamper.upper()
        tag_time_stamp = tag_time_stamp.upper()
        tag_rolling_code = tag_rolling_code.upper()

        tag_flag_tamper_hex = tag_flag_tamper.encode('utf-8').hex()

        """
        Checking UID
        
        1: Seperate UID of SIC43S1's CMAC[394A'21'] and SIC43S1's OCB[394A'10', 394A'20']
        """
        if tag_uid[4:6] == '21':
            #### CMAC ROLLING CODE USE 32 CHARS.####
            tag_rolling_code = tag_rolling_code[:32]

            try:
                conn = sqlite3.connect('./storage.db', isolation_level=None)
                cur = conn.cursor()
                cur.execute("SELECT * FROM s1storage WHERE UID=?", (tag_uid,))
                server_uid, server_key, server_time_stamp, previous_rolling_code = cur.fetchone()
                cur.close()

                server_rolling_code = s1_cmac(tag_time_stamp, tag_uid, tag_flag_tamper_hex, server_key)

                server_time_stamp_int = int(server_time_stamp)
                tag_time_stamp_int = int(tag_time_stamp, 16)

                time_stamp_decision, rolling_code_decision = decision_compare(tag_uid, tag_time_stamp_int, server_time_stamp_int, tag_rolling_code, server_rolling_code)

                return render_template(
                            'index.html',
                            title = 'SIC43S1(CMAC) Demonstration',
                            uid = tag_uid,
                            key = server_key,
                            flag_tamper = tag_flag_tamper,
                            flag_tamper_from_server = 'N/A',
                            flag_tamper_decision = 'N/A',

                            time_stamp_int = tag_time_stamp_int,
                            time_stamp_from_server = server_time_stamp_int,
                            time_stamp_decision = time_stamp_decision,

                            rolling_code = tag_rolling_code,
                            rolling_code_from_server = server_rolling_code,
                            rolling_code_decision = rolling_code_decision
                        )
            except:
                title = "SIC43S1: ERROR! - UID not found or Database error."
            

        elif tag_uid[4:6] == '10' or tag_uid[4:6] == '20':
            #### In Development ####
            # s1_ocb()
            return render_template(
                        'index.html',
                        title = 'SIC43S1(OCB) Demonstration',
                        uid = 'N/A',
                        key = 'N/A',
                        flag_tamper = 'N/A',
                        flag_tamper_from_server = 'N/A',
                        flag_tamper_decision = 'N/A',

                        time_stamp_int = 'N/A',
                        time_stamp_from_server = 'N/A',
                        time_stamp_decision = 'N/A',

                        rolling_code = 'N/A',
                        rolling_code_from_server = 'N/A',
                        rolling_code_decision = 'N/A'
                    )
        else:
            title = "SIC43S1: ERROR! - Wrong UID format."
            pass
    else:
        title = "SIC43S1: ERROR! - Wrong format params."
        pass

    return render_template(
                    'index.html',
                    title = title,
                    uid = 'N/A',
                    key = 'N/A',
                    flag_tamper = 'N/A',
                    flag_tamper_from_server = 'N/A',
                    flag_tamper_decision = 'N/A',

                    time_stamp_int = 'N/A',
                    time_stamp_from_server = 'N/A',
                    time_stamp_decision = 'N/A',

                    rolling_code = 'N/A',
                    rolling_code_from_server = 'N/A',
                    rolling_code_decision = 'N/A'
                )

def decision_compare(tag_uid, tag_time_stamp_int, server_time_stamp_int, tag_rolling_code, server_rolling_code):
    """
    Decision
    
    1: Compare timestamp (tag VS server)
    2: Compare Rolling Code (tag VS server)
    """
    #### COMPARE TIMESTAMP ####
    if tag_time_stamp_int > server_time_stamp_int:
        time_stamp_decision = 'Rolling Code Updated!!'

        conn = sqlite3.connect('./storage.db', isolation_level=None)
        cur = conn.cursor()
        with conn:
            cur.execute("UPDATE s1storage SET TimeStamp=? WHERE UID=?", (tag_time_stamp_int,tag_uid))
        conn.commit()
        cur.close()
    else:
        time_stamp_decision = 'Rolling Code Reused!!'

    #### COMPARE ROLLING CODE ####
    if tag_rolling_code == server_rolling_code:
        rolling_code_decision = 'Correct!!'

        conn = sqlite3.connect('./storage.db', isolation_level=None)
        cur = conn.cursor()
        with conn:
            cur.execute("UPDATE s1storage SET RollingCode=? WHERE UID=?", (tag_rolling_code,tag_uid))
        conn.commit()
        cur.close()
    else:
        rolling_code_decision = 'Incorrect...'   

    return time_stamp_decision, rolling_code_decision


@app.route('/add')
def contact():
    """Renders the add page."""
    return render_template("add.html")

@app.route('/', methods=['POST'])
def added():  
    try:
        uid_params = request.form['uid'].upper()
        if len(uid_params) != 14:
            uid_params = None

        key_params = request.form['key'].upper()
        if len(key_params) != 32:
            key_params = None

    except:
        uid_params = None
        key_params = None

    if uid_params is None or key_params is None:    
        return render_template('result.html',
            head = 'SIC43S1 Add UID Failure..',
            uid = 'Need UID: 14 chars',
            key = 'Need Key: 32 chars'
        )
    else:
        conn = sqlite3.connect('./storage.db', isolation_level=None)
        cur = conn.cursor()
        try:
            #### ADD UID ####
            cur.execute("INSERT INTO s1storage (UID, Key, TimeStamp, RollingCode) VALUES (?,?,?,?)",
                        (uid_params, key_params, -1, '0'))
            conn.commit()
            head_params = 'SIC43S1 Add UID Successful!!'
        except Error as ee:
            #### UPDATE UID ####
            if 'UNIQUE' in str(ee):
                cur.execute("UPDATE s1storage SET Key=? WHERE UID=?", (key_params,uid_params))
                conn.commit()
                head_params = 'SIC43S1 Update UID or Key Successful!!'
            else:
                head_params = 'SIC43S1 Add UID Failure..',
                uid_params = 'Wrong pattern'
                key_params = 'Wrong pattern'
            cur.close()

        return render_template("result.html",
                head = head_params,
                uid = uid_params,
                key = key_params
        )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
