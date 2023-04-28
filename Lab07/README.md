# Lab07

## Run PoC

```sh
make
./bmpgrayscale PoC.bmp out.bmp
```

## Steps of lab

```sh
export CC=~/AFL/afl-gcc
export AFL_USE_ASAN=1
make
mkdir in
cp test.bmp in/
sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
cd /sys/devices/system/cpu && echo performance | sudo tee cpu*/cpufreq/scaling_governor && cd -
~/AFL/afl-fuzz -i in -o out -m none -- ./bmpgrayscale @@ a.bmp
```

## Screenshot of AFL

![image](https://user-images.githubusercontent.com/16871628/235046601-399f9ac5-8a02-4022-9983-8001ccf30aab.png)

## Crash detail

![image](https://user-images.githubusercontent.com/16871628/235046906-31d28122-d608-4fe8-8715-09cb6d5a93ca.png)
