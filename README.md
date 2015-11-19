# repofinder
find a what versions are in which environments

Clone the repo and build with

make goinstall

To build for other architectures 

make GOOS=$(os) GOARCH=$(arch)

const goosList = "android darwin dragonfly freebsd linux nacl \ 
  netbsd openbsd plan9 solaris windows "

const goarchList = "386 amd64 amd64p32 arm arm64 ppc64 ppc64le \
   mips mipsle mips64 mips64le mips64p32 mips64p32le \ # (new)
   ppc s390 s390x sparc sparc64 " # (new)
