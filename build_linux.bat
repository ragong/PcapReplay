set GOOS=linux
set GOARCH=amd64
set BUILD_NAME=PcapReplay
set SOURCE=.
go.exe build -ldflags "-s -w" -o %BUILD_NAME% %SOURCE%
