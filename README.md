## A TrueCrypt compatible cryptographic filesystem layer for FreeBSD

This is actually quite an old project (I guess I started it around 2010 or so), 
but I thought I'd share it anyway. Some years ago, I was in the situation of 
having to mount TrueCrypt images on my [FreeBSD](http://www.freebsd.org) 
machines. As there is no working FreeBSD port of TrueCrypt (to the best of my 
knowledge), I decided to do a tiny implementation myself.

Thanks to the [geom\_gate](http://people.freebsd.org/~pjd/pubs/GEOM_Gate.pdf) 
interface, creating block devices that are backed by userland code is pretty
easy in FreeBSD. The Linux version of TrueCrypt makes use of FUSE in combination
with loopback devices (ouch). The TrueCrypt file format itself is pretty
straight-forward. I would love to say it's well-documented, but this isn't
exactly the case. The [documentation](http://www.truecrypt.org/docs/) isn't 
always accurate. However, after some trial-and-error, I was able to build a C 
implementation that works for me. It should probably re-written by a better
coder and I'm not going to claim that it's secure either. Still, it can serve as
a PoC of how a FreeBSD TrueCrypt could look like.

The code still has some issues. It is not possible to use key files.  Only
simple encrypted volumes are supported. No fancy hidden volumes or full system
encryption. And of course there are probably quite some bugs / missing features
I just don't know about.

_WARNING_: This may or may not work! I'm not making *any* security claims here.
Really, please consider this code just as a PoC!

### Building
The build process is rather straight:
<pre>
make
</pre>

You can now try the code using an existing TrueCrypt container. Please be
careful, don't use a container that contains any important data.
<pre>
sudo kldload geom_gate
./ggateTruecrypt create container.tc
sudo mount -t msdosfs /dev/ggate0 /mnt
</pre>

