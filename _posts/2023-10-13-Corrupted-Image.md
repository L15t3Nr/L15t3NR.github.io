---
title: Manual Recovery of Location Data From JPG
date: 2023-10-13 12:00:00 -0500
author: L15t3Nr
categories:
  - WriteUp
  - Digital Forensics
tags:
  - WriteUp
img_path: /assets/img/Corrupted Image
permalink: /posts/Corrupted-Image/
---
![img-1](/assets/img/Corrupted-Image/img-1.png)



This post is a walkthrough of how to manually recover location data from an image using a hex editor (HxD). I will provide two methods for doing this.

I will be using an intentionally corrupted image that I created. If you'd like to try it yourself, you can open this image in a new tab and download it, then open it in a hex editor. 
![Corrupted Image](/assets/img/Corrupted-Image/Corrupted-img-2.jpg)

Most of the image data has been overwritten with null values, which is why the image doesn't display anything when its opened. This is meant to simulate what might happen if the image file were deleted and partially overwritten, but without the complicated overwritten data and just null values instead. There is just enough data remaining from the original image for it to be identified as a valid image and the important EXIF data still remains in the file! All of this data can be viewed using a Hex Editor such as HxD. 

# EXIF Tool (Simple Method)

You might try taking the jpg file and using an online EXIF tool to view the location data. 

![Exif Tool](/assets/img/Corrupted-Image/img-2.png)

Unfortunately, this won't return any of the useful EXIF information. This has to do with the TIFF Header Structure of this corrupted image. TIFF stands for Tag Image File Format and its used to represent [raster graphics](https://en.wikipedia.org/wiki/Raster_graphics)(2-D Images as a grid of pixels) and store image information (like location data or created date). 

![HxD](/assets/img/Corrupted-Image/img-3.png)

When looking at a JPG in a hex editor, the first few offsets of the file contain some important information for the EXIF tool to identify the image and the metadata it has. 

`FF D8` is at offset 0 and 1, and identifies the start of a JFIF, JPE, JPEG, or JPG. These offsets are crucial for the EXIF tool. If these offsets were missing, the EXIF tool would not recognize this file as a JPG. 

There is also a trailer `FF D9` which identifies the end of the file. 

The next few offsets can optionally contain an EXIF Tool tag name or an SPIFF tag name. This data has been tampered with, `DE AD BE EF` spells `DEADBEEF` and doesn't provide any useful information other than that the files data has been tampered with. These offsets aren't important for the EXIF tool in finding the metadata anyways. 

Offset `12` is where the fun begins and leads towards the first solution of this challenge. 

The start of the TIFF Header Structure can begin with either `4D 4D` (MM in ascii) or `49 49` (II in ascii). Here, there is a `4D` for an M, but only just one. If you are clever and realize there should be two M's, you might change the null value at offset `13` to `4D`, save the change and reupload the image to an EXIF Tool. 

![Changed](/assets/img/Corrupted-Image/img-4.png)

![Exif](/assets/img/Corrupted-Image/img-5.png)

![Exif](/assets/img/Corrupted-Image/img-6.png)

With this simple change the exiftool has everything it needs to identify all the IFD entries, including the location data. 

![Well Done](/assets/img/Corrupted-Image/well-done.gif)

BUT...if you are an intellectually starving nerd like myself, you might push on to understand where this data actually lives in the file. Why? Because why not? You can't just leave knowledge on the table. 

# Image File Directory (IDF) Searching for GPS Data

**Byte Order and IFD Offset**

The TIFF Header Structure is 8 bytes long. 


![8-byte-tiff.png](/assets/img/Corrupted-Image/8-byte-tiff.png)

| Bytes | Hex Values | Meaning |
| ---- | ---- | ---- |
| 0 to 7 | `4D 4D 00 2A 00 00 00 08` | 8-Bytes |
| 0 to 1 | `4D 4D` | Byte Order |
| 2 to 3 | `00 2A` | TIFF File |
| 4 to 7 | `00 00 00 08` | Offset of the first IFD |

**Image File Directory**

This is where the image data pointers and metadata are stored. This directory could come before or after the actual image data itself. 

In this case, the IFD0 is located at offset 8. This is heavily confusing because we just looked at offsets 12 to 19 to see the 8 byte TIFF Header Structure. What this offset 8 byte value actually means is to start from the beginning of the TIFF File. The TIFF file began at offset 12 with a value of `4D`. We need to add 8 bytes starting from offset 12 and look at the next bytes to see the first IFD entry. 

To put it another way, we can add 12 bytes from the very beginning of the file. 

**IFD0**


![IFD0](/assets/img/Corrupted-Image/IFD0.png)


| Bytes | Hex Value | Meaning |
| ---- | ---- | ---- |
| + 02 | `00 0D` | 13 Directory Entries |
| + 12 | `01 00 00 03 00 00 00 01 0F C0 00 00` | Entry 0 |
| + 12 | `01 01 00 03 00 00 00 01 0B D0 00 00` | Entry 1 |
| + 12 | `01 0F 00 02 00 00 00 08 00 00 00 AA` | Entry 2 |
| + 12 | `01 10 00 02 00 00 00 09 00 00 00 B2` | Entry 3 |
| + 12 | `01 12 00 03 00 00 00 01 00 01 00 00` | Entry 4 |
| + 12 | `01 1A 00 05 00 00 00 01 00 00 00 BC` | Entry 5 |
| + 12 | `01 1B 00 05 00 00 00 01 00 00 00 C4` | Entry 6 |
| + 12 | `01 28 00 03 00 00 00 01 00 02 00 00` | Entry 7 |
| + 12 | `01 31 00 02 00 00 00 0E 00 00 00 CC` | Entry 8 |
| + 12 | `01 32 00 02 00 00 00 14 00 00 00 DA` | Entry 9 |
| + 12 | `02 13 00 03 00 00 00 01 00 01 00 00` | Entry 10 |
| + 12 | `87 69 00 04 00 00 00 01 00 00 00 EE` | Entry 11 |
| + 12 | `88 25 00 04 00 00 00 01 00 00 03 1E` | Entry 12 |
| + 04 | `00 00 00 00` | Offset to next IDF (None) |

The first 2 bytes tell us that there are 13 12-byte entries that follow. Then the next IFD is pointed to at the end.  

**12-Byte Field Entry 0 Breakdown**

The first 12 bytes are broken down as follows:


| Bytes | Hex Value | Meaning | Information |
| ---- | ---- | ---- | ---- |
| 0 to 11 | `01 00 00 03 00 00 00 01 0F C0 00 00` | IFD Entry 0 | 12-Bytes |
| 0 to 1 | `01 00` | Field Identifying Tag | 256 = [Exif.Image.ImageWidth](https://exiftool.org/TagNames/EXIF.html) |
| 2 to 3 | `00 03` | Field Type | SHORT (2 byte unsigned integer) |
| 4 to 7 | `00 00 00 01` | Count of the Type | 1 count |
| 8 to 11 | `0F C0 00 00` | The Value Offset | 0FC0 = 4032 |


Bytes 8 to 11 don't actually point to an IFD value offset. Rather, the value of the image width is recorded here instead since it fits in 4 bytes or less. The value is the first 4 bytes starting from the left. `0F C0` means the width is 4032 and this is confirmed by looking back at the EXIF tool results: 


![Exif](/assets/img/Corrupted-Image/img-5.png)

The 12 byte field entries contain the metadata we want to view. In this first directory entry we looked at the Exif.Image.ImageWidth data. Using an Exif tags table as a reference, we can look for the directory entry that has GPS Info.

**GPS Info Tag**

The GPS info tag has the hex value of `8825` and can be searched for within the 13 12-byte entries. 


![GPS-info-tag](/assets/img/Corrupted-Image/GPS-Info-Tag.png)

Looking back at the table above, the 13th directory entry contains an Exif Tag for GPS info. 

**12-byte breakdown of IFD Entry 13**

| Byte | Hex | Meaing | Information |
| ---- | ---- | ---- | ---- |
| 0 to 11 | `88 25 00 04 00 00 00 01 00 00 03 1E` | IFD Entry 13 | 12-Bytes |
| 0 to 1 | `88 25` | Field Identifying Tag | GPSTag |
| 2 to 3 | `00 04` | Field Type | LONG (4 byte unsigned integer) |
| 4 to 7 | `00 00 00 01` | Count of the Type | 1 count |
| 8 to 11 | `00 00 03 1E` | The Value Offset | Offset 798 |

Starting from the beginning of the TIFF File, the GPS IFD should start at offset 798 and what follows is a new IFD with its own number of 12-byte entries and values.


![GPS-Info-IFD](/assets/img/Corrupted-Image/GPS-Info-IFD.png)

Following the same IFD structure of 2-byte number of entries and then x number of 12-byte entries, we can determine what this IFD has in it. 

**GPS Info IFD Breakdown**

| Bytes | Hex | Meaning |
| ---- | ---- | ---- |
| 0 to 1 | `00 09` | 9 Directory Entries |
|  | `00 01 00 02 00 00 00 02 4E 00 00 00` | Entry 0 |
|  | `00 02 00 05 00 00 00 03 00 00 03 90` | Entry 1 |
|  | `00 03 00 02 00 00 00 02 57 00 00 00` | Entry 2 |
|  | `00 04 00 05 00 00 00 03 00 00 03 A8` | Entry 3 |
|  | `00 05 00 01 00 00 00 01 00 00 00 00` | Entry 4 |
|  | `00 06 00 05 00 00 00 01 00 00 03 C0` | Entry 5 |
|  | `00 07 00 05 00 00 00 03 00 00 03 C8` | Entry 6 |
|  | `00 1B 00 07 00 00 00 0C 00 00 03 E0` | Entry 7 |
|  | `00 1D 00 02 00 00 00 0B 00 00 03 EC` | Entry 8 |
|  | `00 00 00 00 00` | Offset to Next IFD (None) |

There are 9 directory entries in this GPS Info IFD. A [GPS Info Tag](https://exiftool.org/TagNames/GPS.html) reference can be used to identify the field tags. 


| Entry # | Field Tag | Field Type | Count | Value |
| ---- | ---- | ---- | ---- | ---- |
| 0 | GPSLatitudeRef | ASCII | 2 | N |
| 1 | GPSLatitude | RATIONAL | 3 | Value at offset 0390 = 42 58 13.1555 |
| 2 | GPSLongitudeRef | ASCII | 2 | W |
| 3 | GPSLongitude | RATIONAL | 3 | Value at offset 03A8 = 85 40 13.7531 |
| 4 | GPSAltitudeRef | BYTE | 1 | 0 = Above Sea Level |
| 5 | GPSAltitude | RATIONAL | 1 | Value at offset 03C0 = 180.552 |
| 6 | GPSTimeStamp | RATIONAL | 3 | Value at offset 03C8 =  23:28:24 UTC |
| 7 | GPSProcessingMethod | UNDEFINED | 12 | Skip |
| 8 | GPSDateStamp | ASCII | 11 | Value at offset 03EC = 2023:09:27 |

Each RATIONAL Field Type consists of 2 LONGs. The first LONG is the numerator and the second LONG is the denominator. I converted the hex values to their decimal value and divided. 

As an example, Entry 1 contains 3 RATIONAL values. 

The first value is a LONG at offset 0390 is `00 00 00 2A` (42) followed by the second LONG `00 00 00 01` (1)
The second value is `00 00 00 3A` (58), followed by the second LONG `00 00 00 01` (1)
The third value is a LONG `00 02 01 E3 `(131555) and the second LONG `00 00 27 10` (10000)
After dividing 131555 by 10000 you have 13.1555. 

The 3 RATIONAL values are in a Degrees, Minutes, Seconds format. 
`42° 58' 13.155"`

The Final Coordinates are: 
`42° 58' 13.155" N`
`85° 40' 13.7531" W`

![Exif](/assets/img/Corrupted-Image/img-6.png)


**Ta-Da**

![Ta-Da](/assets/img/Corrupted-Image/Christoph-Waltz-Ta-Da-GIF.gif)

These coordinates are for this address:
```
United States District Court for the Western District of Michigan
110 Michigan Street Northwest, Grand Rapids, MI 49503 
United States of America
```


The original, uncorrupted image: 
![Original](/assets/img/Corrupted-Image/Original_IMG.jpg)


# References:

https://www.garykessler.net/library/file_sigs.html
https://www.cipa.jp/std/documents/e/DC-008-2012_E.pdf
https://exiv2.org/tags.html
https://docs.fileformat.com/image/exif/
https://exiftool.org/TagNames/GPS.html