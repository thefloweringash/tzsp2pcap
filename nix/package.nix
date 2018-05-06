{ stdenv, libpcap }:

stdenv.mkDerivation rec {
  name = "tzsp2pcap";

  src = stdenv.lib.cleanSource ../.;

  buildInputs = [ libpcap ];

  installPhase = ''
    mkdir -p $out/bin
    make install DESTDIR=$out
  '';
}
