Command line used to find this crash:

./afl-fuzz -t 8000000+ -w 150 -b 14 -y 86400 -m none -i /STAFF/FirmAE/scratch/aflnet_base_5/1/inputs -o /STAFF/experiments/exp_90/outputs -x keywords -D 58.347187196 -N tcp://192.168.1.1/80 -P HTTP -R -X -QQ -- ./qemu-system-mipsel -m 1024 -M malta -kernel /STAFF/FirmAE/binaries//vmlinux.mipsel.4_DECAF -drive if=ide,format=raw,file=/STAFF/FirmAE/scratch/aflnet_base_5/1/image.raw -serial file:qemu.final.serial.log -serial unix:/tmp/qemu.1.S1,server,nowait -monitor unix:/tmp/qemu.1,server,nowait -display none -rtc base=localtime,clock=host -device e1000,netdev=net0 -netdev tap,id=net0,ifname=tap_ab_5_1_0,script=no -device e1000,netdev=net1 -netdev tap,id=net1,ifname=tap_ab_5_1_1,script=no -device e1000,netdev=net2 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net3 -netdev socket,id=net3,listen=:2003 -append root=/dev/sda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 init=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL=true FIRMAE_ETC=true user_debug=0 firmadyne.syscall=1 nokaslr norandmaps libata.force=noncq libata.force=pio4 --aflFile @@

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
