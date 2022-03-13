#write a new ASPX file
aspxfile_open=open('payloads/ASPX/shellcode_runner.aspx', 'r')
aspx_code = aspxfile_open.read()
aspxfile_open.close()

with open('Templates/ASPX/shellcode_runner_template.aspx') as aspxfile:
        aspxdata = aspxfile.read()
replace=aspxdata.replace('PUT_ASPX_CODE_HERE', aspx_code)

#Write a new ASPX file
with open('payloads/ASPX/web.config', 'w') as aspxfile:
  aspxfile.write(replace)
