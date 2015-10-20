Assignment 2: Incident Alarm
By: Susannah Church
COMP 116

1) Identify what was correctly implemented and what was not.
I believe almost everything was correctly implemented.
It seems as though on my livestream, nmap scan is not 
behaving properly but I cannot tell if this is the fault of 
the network or my code. It is suspicious since the nmap scan
is working properly for the log and they are the same function.
Also, the payload for the web server long was a little tricky
since there are a couple of different options for choosing what
the "payload" was. For most of these scans, it was the final
data at the end of the line, but for shellcode all of the actual
shellcode exsisted earlier on in the line and was thus not
considered part of the payload.

2) Who did you collaborate or discuss this assignment with?
Ming Chow, Margaret Feltz, Melissa Blotner

3) Approximately how many hours did you spend on this assignment?
Probably between 8-10, but I lost 50% of my work when I was 
about 75% done and then ran into some pretty nasty bugs.

4) The heuristics used in this assignment are not very good. As noted
in a couple of my functions, there are so many different things to
search for when scanning for one datapoint. myPhpAdmin shows up at least
5 different ways in the one sample web server log we received, and after
a while it becomes unreasonable to search for each individual piece
of text. Similarly, scanning for any leaked credit card number is impossible.
For most of these incidents, there are only so many instances you can catch
with these kinds of general heuristics.
5) If I had spare time in the future, my first move would be to improve
my regexs. Using more advance regular expressions would surely catch
more incidents. However, if we wanted this incident detection model to scale,
my next move would mostlikely be to add some kind of machine learning application into the detection system so that the program could dynamically increase its knowledge of what an incident that needs to alert the sysadmin looks like. 
