.PHONY: all
all: build/goblkid

u-root:
	git submodule update --init --recursive

# build code
build/goblkid: | build
	go build -ldflags=$(LDFLAGS) -o $@ cmds/goblk.go

u-root.bin: u-root
	cd u-root && \
	go build && \
	mv u-root ../u-root.bin

./vendor:
	go mod vendor

build:
	mkdir build

clean: clean-bb
	rm -rf build

clean-bb:
	find . -name ".bb" | xargs rm -rf

spotless: clean
	rm -rf vendor
	rm -rf u-root u-root.bin

lint: bin/golangci-lint
	./bin/golangci-lint run --enable-all ./...

bin/golangci-lint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.24.0

define commands
	./u-root.bin -format=cpio -build=bb -o build/$1.cpio \
		-defaultsh /bbin/elvish \
		github.com/u-root/u-root/cmds/core/{cat,chmod,cp,df,echo,elvish,find,grep,insmod,kill,ls,lsmod,mkdir,mount,pwd,rm,rmmod,umount} \
		github.com/u-root/u-root/cmds/exp/{rush,modprobe} \
		github.com/isi-lincoln/goblkid/cmds/$2
	./utils/update-cpio.sh build/$1.cpio $1-initramfs.cpio
endef
