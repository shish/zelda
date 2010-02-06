                   __________     .__       .___       
                   \____    /____ |  |    __| _/____   
                       /   // __ \|  |   / __ |\__  \  
                    __/   /\  ___/|  |__/ /_/ | / __ \_
                   /_______ \___  >____/\____ |(____  /
                           \/   \/           \/     \/ 

A tool to turn plain text apache formatted logs into a binary format. Binary
logs are around 15% the size of plain text, and compressed binary is around
50% smaller than compressed text.

Usage:
 o) ./zelda.py access.log
    will output access.log.loz
 o) ./zelda.py access.log.loz
    will output access.log.loz.deloz
 o) Both modes accept a second argument to specify a different output file

Example compression:
 o) The maximum-compression.com "fighter-planes.com" benchmark
        20617071 fp.log               # original, 20MB
         3329095 fp.log.loz           # loz, 3.5MB
          708531 fp.log.lzma          # compressed original, 700KB
          450750 fp.log.loz.lzma      # compressed loz, 450KB
 o) One of my own websites, around 5 million log entries:
      1342318213 access.log           # original, 1.3GB
       200853665 access.log.loz       # loz, 200MB
        74790313 access.log.lzma      # compressed original, 75MB
        41398420 access.log.loz.lzma  # compressed loz, 40MB

Speed:
 o) The 1.3GB dataset is compressed in under 4 minutes on my Pentium-M 1.7GHz
    laptop; the entire development process of v0.1 of this program was faster
    than piping the file through lzma, once, on a 2.8GHz box :-)
 o) Decompression of that dataset takes under 2 minutes

Accuracy:
 o) Timezone is assumed to be constant, though there is room within
    the format to allow a "change timezone" escape code, but this is
    currently unimplemented
 o) For files where the timezone doesn't change:
      0b52bbe953337e9b9c6b80da707d2403  access.log
      0b52bbe953337e9b9c6b80da707d2403  access.log.loz.deloz
 o) Corrupt lines (of which my test dataset has many) are escaped and stored
    as plain text


