import string
import subprocess

for letter in string.printable:
    if letter == "'":
        echo = "echo " + '"' + letter + '"'
    else:
        echo = "echo " + "'" + letter + "'"
    print("testing " + echo + " | ./mildly_evil")
    output = subprocess.check_output(echo + " | ./mildly_evil", shell=True)

    if output != "Wrong\n":
        print("found! " + letter)
        break

