# Vagrant boxes collection

This folder contains scripts and a collection of vagrant boxes which can be
useful to test eBPF programs under different kernels.

| Box        | Kernel | Notes                                                 |
|------------|--------|-------------------------------------------------------|
| ubuntu2004 |    5.4 | Won't work because the lack of `bpf_probe_read_kernel`|
| ubuntu2010 |    5.8 |                                                       |
| archlinux  |   5.17 |                                                       |

Example usage:

```
$ ./vagrant/static.sh
...this script will use `x86_64-unknown-linux-musl` to make 
...an all-static build of pulsar and its test suite.
$ cd vagrant/archlinux
$ vagrant up
$ vagrant ssh
[vagrant@archlinux ~]$ for test in /vagrant/tests/*; do ./${test}; done
...unit tests are run, highlighting to eBPF incompatibilities
[vagrant@archlinux ~]$ sudo /vagrant/probe --file-created
...sample program to display all events is run
Ctrl-C
[vagrant@archlinux ~]$ sudo RUST_LOG=info /vagrant/pulsar-exec pulsard
...pulsard output
Ctrl-C
[vagrant@archlinux ~]$ exit
$ vagrant halt
```

# Common issues

## ssh issues

If `vagrant up` doesn't complete, make sure ssh-rsa keys are enabled:
```
echo PubkeyAcceptedKeyTypes=+ssh-rsa | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd
```

This happened on ubuntu 21.10 when running archlinux.

