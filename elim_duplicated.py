import os

txt_path = './crash_trimmed/'
out_path = './unique_crashes/'
errors = {}
files = os.listdir(txt_path)
ctr = 0


for file in files:
	idx = file.split('.')[0].split('_')[1]
	f = open(txt_path+str(file), 'r')
	addrlist = []
	while  True:
		line = f.readline()
		if line =='':
			break
		addr = line.split()[1]
		
		if not len(addr) > 9:
			addrlist.append(addr)

		error = frozenset(addrlist)
		pass
	f.close()
	if not error in errors:
		errors[error] = idx
		fw = open(out_path+"crash "+str(idx),'w')
		fw.write('hi')
		fw.close()
	else:
		print('duplicated')


