import re
import csv

def save_to_file(kakao):
  file = open(f"kakao.csv", mode="w")
  writer = csv.writer(file)
  writer.writerow(["sender", "cipher", "time", "enc"])
  for k in kakao:
    writer.writerow(list(k.values()))
  return

def byte_to_dec(s, ids):
    id = s.hex()
    id = int(id, 16)
    if id in ids:
      pass
    else:
      ids[s] = id
    return ids

def extract_message(data):
	p = re.compile(b'([\s\S]{4}[a-zA-Z0-9+/={}]*[\^_]{1}[\s\S]{1,100})?({[^}]*"enc":[^}]+})')
	result = p.findall(data)

	ps = re.compile(b'^[\s\S]{4}') # sender
	pc = re.compile(b'[a-zA-Z0-9+/={}]+') # cipher
	pt = re.compile(b'\d{2}-\d{2} \d{2}:\d{2}:\d{2}') # time
	pe = re.compile(b'\"enc\":\d\d')

	kakao = list()
	ids = dict()
	for r in result:
	      s = ps.findall(r[0])
	      if s:
	      	s = s[0]
	      	if s not in ids:
	      		byte_to_dec(s, ids)
	      	s = ids[s]
	      else:
	      	s = 'None'
	      c = pc.findall(r[0][4:])
	      if c:
	      	c = c[0]
	      else:
	      	c = 'None'
	      t = pt.findall(r[1])
	      if t:
	      	t = t[0]
	      else:
	      	t = 'None'
	      e = pe.findall(r[1])
	      if e:
	      	e = e[0][-2:]
	      else:
	      	e = 'None'

	      kakao.append({'sender':s, 'cipher':c, 'time':t, 'enc':e})

	save_to_file(kakao)

def extract():
	try:
		f = open(args.file, 'rb')
		data = f.read()
	except:
		# adb shell su -c "dd if=/dev/block/mmcblk0" > image.dd)
		print(f'can\'t open file \'{args.file}\'.')
		return
		
	extract_message(data)
	print("✔Create kakao.csv\n")