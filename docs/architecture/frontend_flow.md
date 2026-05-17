Frontend flow:

1. frontend require user to input information to access the nginx config as shown in configs/before_remediation.json
2. user provide info and approve the app to access the user's server for nginx config, once approved, app will save info, use that to retrieve config files from inputted server, and save it to system.
3. System quick check for config syntax (using nginx -t), if fail, system reports it.
4. system scan config for problems and show to user
5. after user proceed, system generate a fix to the config, showing diff for user to view manually.

- NOTE. some scanner/security guideline doesn't have one correct way to fix things, on that case, the fix fragment corresponding to the guideline will require user to input the params for the fix (e.g. choose from an option list or manually type in).

6. User input fix params if any. then one of two case happens:

- if no fix with required user input presents, user press approve, the system then show a button that when clicked, the system overwrite the nginx config in the destination server. If input is present, the system then apply the user input and generate a final version of config, run it against syntax checks and give final verdict. If everything passes, continues as above.
