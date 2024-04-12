docker build -t facefish-config-container -f ./Dockerfile .
docker run --rm --volume "./:/root/go/src/facefishconfig/" -i facefish-config-container <<EOF

cd /root/go/src/facefishconfig/
go build -ldflags '-s -w -extldflags "-static"' -trimpath -buildvcs=false -o /root/go/src/facefishconfig/facefishconfig.win64.exe -tags yara_static -buildmode=exe

zip -r facefishconfig.zip facefishconfig.win64.exe rules.yar
EOF