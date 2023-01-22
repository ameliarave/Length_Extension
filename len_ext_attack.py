!/usr/bin/python3
# Run me like this:
# $ python3 len_ext_attack.py "https://project1.eecs388.org/uniqname/lengthextension/api?token=...."

import sys
from urllib.parse import quote
from pymd5 import md5, padding, _decode


class ParsedURL:
    def __init__(self, url: str):        
        self.prefix = url[:url.find('=') + 1]               # prefix is the slice of the URL from "https://" to "token=", inclusive.
        self.token = url[url.find('=') + 1:url.find('&')]           
        self.suffix = url[url.find('&') + 1:]               # suffix starts at the first "command=" and goes to the end of the URL


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} URL_TO_EXTEND", file=sys.stderr)
        sys.exit(-1)

    url = ParsedURL(sys.argv[1])
    raw_msg_size = 8 + len(url.suffix)      # in bytes
    pad1 = padding(raw_msg_size*8)          # 64-bit pwd + suffix-bits    
    pad1_count_bytes = pad1[-8:]
    pad1_count_int = int.from_bytes(pad1_count_bytes, "little")     # integer bit-length of unpadded m [pwd || suffix]
    m_pad_len = pad1_count_int + (len(pad1)*8)                      # [num_bits in unpadded msg] + [num_bits in padding to be appended] = num_bits in padded_msg to be hashed 

    h = md5(state=bytes.fromhex(url.token), count=m_pad_len)        # seed h with most recent output of hashing m + padding, tell it how many bits for next padding calculation    
    h.update("&command=UnlockSafes")                                # add length extension "unlock safes" to md5 msg
    token2 = h.hexdigest()                                          # hash the extended url giving us token2

    modified_url = url.prefix + token2 + "&" + url.suffix + quote(pad1) + "&command=UnlockSafes" # + escaped padding + "&command=UnlockSafes"
    # construct url-to-be-used and give it token2, add escaped pad1 to end of original url, then add "&command=UnlockSafes" to end

    print(modified_url)
