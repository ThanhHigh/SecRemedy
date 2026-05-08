First copy from the intergration into tmp
Then get all the files from x_to_y_uncomply folder paste all the files inside each folder into tmp

After that tmp/ will have nginx_raw_22xx/ list of files like that

Next check inside tmp/config_for_test. use these 3 of config files to run
config_input_remedy_toFinal.json (To run remedyEng)
config_input_scanner_before_toFinal.json (To run parser and scanner before remedy)
config_input_scanner_after_toFinal.json (To run scanner after run remedy)

Begin run test
In terminal

- Run set up enviroment first

python -m core.scannerEng.parser --config tests/config_to_test/config_input_scanner_before_toFinal.json

python -m core.scannerEng.scanner --config tests/config_to_test/config_input_scanner_before_toFinal.json

python -m core.remedyEng.run_remedy --config tests/config_to_test/config_input_remedy_toFinal.json

python -m core.scannerEng.scanner --config tests/config_to_test/config_input_scanner_after_toFinal.json

You can see the output files in tmp/contracts and the result score info is in terminal
