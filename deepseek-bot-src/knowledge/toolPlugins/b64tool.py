import sys,json,base64
t=json.loads(sys.argv[1]).get("text","")
print(base64.b64decode(t).decode())