:: Build the executable
pyinstaller "main.spec"
:: Copy the two files of interest into the Autopsy plugin directory - overwrite if necessary
xcopy /y "dist\VNG_zalo_parser.exe" "%appdata%\autopsy\python_modules\Zalo"
xcopy /y "VNGZalo_Parser.py" "%appdata%\autopsy\python_modules\Zalo"

