import obexftp
cli=obexftp.client(obexftp.BLUETOOTH)
#channel=obexftp.browsebt('78:9E:D0:B6:D1:52',obexftp.PUSH)
#print channel #it is the correct channel, I've doubled checked
cli.connect ('78:9E:D0:B6:D1:52',4)
cli.put_file("file.txt") #I also noticed you need to wait a second before this
cli.disconnect()
