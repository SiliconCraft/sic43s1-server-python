import sys
import mycrypto.ocb

# Override PyCryptodome's OCB module
sys.modules['Crypto.Cipher._mode_ocb'] = mycrypto.ocb

from flask import request, render_template, Flask
from verify import s1_cmac, s1_ocb

app = Flask(__name__)

@app.route("/")
def home():
    """
    Preparing Params

    Get parameters from URL
    """
    tag_uid = request.args.get('U')
    tag_temporary_flag = request.args.get('TF')
    tag_timestamp = request.args.get('TS')
    rlc_param = request.args.get('RLC')
    sac_param = request.args.get('SAC')

    if sac_param is not None:
        tag_sac = sac_param
    else:
        tag_sac = rlc_param
        
    tag_timestamp_int = int(tag_timestamp, 16) if tag_timestamp is not None else None
    key_default = "FFFF" + tag_uid + tag_uid if tag_uid is not None else "N/A"

    if tag_uid is not None and tag_temporary_flag is not None and tag_timestamp is not None and tag_sac is not None:
        if len(tag_uid) == 14 and len(tag_temporary_flag) == 2 and len(tag_timestamp) == 8 and (len(tag_sac) == 32 or len(tag_sac) == 90):          
          """
          Checking UID
          
          Seperate UID of SIC43S1's CMAC[394A'21'] and SIC43S1's OCB[394A'10', 394A'20']
          """
          if tag_uid[4:6] == "21":
            # CMAC mode
            is_ocb = False
            
            tag_sac = tag_sac[:32]
            tag_temporary_flag_hex = tag_temporary_flag.encode('utf-8').hex()
            server_sac = s1_cmac(tag_timestamp, tag_uid, tag_temporary_flag_hex, key_default)
            
            """
            Comparing SAC from tag and server
            """
            if tag_sac.upper() == server_sac:
              sac_status = "Correct"
            else:
              sac_status = "Incorrect"
            
            return render_template('index.html',
                                   title = "SIC43S1(CMAC) Demonstration",
                                   is_ocb = is_ocb,
                                   uid = tag_uid,
                                   key = key_default,
                                   tag_temporary_flag = tag_temporary_flag,
                                   tag_timestamp_int = tag_timestamp_int,
                                   tag_sac = tag_sac,
                                   server_sac = server_sac,
                                   sac_status = sac_status
                                   )
            
          elif tag_uid[4:6] == "10" or tag_uid[4:6] == "20":
            # OCB mode
            is_ocb = True
            tag_ciphertext = tag_sac[:82]
            tag_mac = tag_sac[82:]
            
            server_plaintext, server_mac = s1_ocb(tag_timestamp, tag_ciphertext, tag_mac, key_default)
            
            user_data = server_plaintext[:64]
            server_uid = server_plaintext[64:78]
            server_temporary_flag_ascii = server_plaintext[78:]
            
            server_temporary_flag = bytes.fromhex(server_temporary_flag_ascii).decode('utf-8')
            
            if(tag_mac.upper() == server_mac.upper()):
              sac_status = "Correct"
            else:         
              sac_status = "Incorrect"
              
            if(tag_uid.upper() == server_uid.upper()):
              uid_status = "Correct"
            else:
              uid_status = "Incorrect"
              
            if(tag_temporary_flag.upper() == server_temporary_flag.upper()):
              temporary_flag_status = "Correct"
            else:
              temporary_flag_status = "Incorrect"

            return render_template('index.html',
                                   title = "SIC43S1(OCB) Demonstration",
                                   is_ocb = is_ocb,
                                   uid = tag_uid,
                                    key = key_default,
                                    tag_sac = tag_sac,
                                    server_sac = "TAG: " + server_mac,
                                    sac_status = sac_status,
                                    tag_timestamp_int = tag_timestamp_int,
                                    server_user_data = user_data,
                                    server_uid = server_uid,
                                    uid_status = uid_status,
                                    tag_temporary_flag = tag_temporary_flag,
                                    server_temporary_flag = server_temporary_flag,
                                    temporary_flag_status = temporary_flag_status
                                   )
        else:
          title = "Input Parameters are not in correct format"
      
      
        return render_template('index.html', title= title)
    else:
      if tag_uid is None:
        tag_uid = "N/A"
        
      if tag_temporary_flag is None:
        tag_temporary_flag = "N/A"
        
      if tag_timestamp is None:
        tag_timestamp = "N/A"
        
      if tag_sac is None:
        tag_sac = "N/A"
        
      return render_template('index.html', 
                             is_ocb=None, 
                             title='Input Parameters are empty', 
                             uid= tag_uid, 
                             key=key_default,
                             tag_temporary_flag = tag_temporary_flag,
                             tag_timestamp_int = tag_timestamp_int if tag_timestamp_int is not None else "N/A",
                             tag_sac = tag_sac,
                             server_sac = "N/A",
                             sac_status = "N/A"
                             )