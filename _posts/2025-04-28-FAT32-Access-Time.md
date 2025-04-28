---
title: "Sunday Funday # 814 - FAT32 Access Time"
date: 2025-04-20 12:00:00 -0500
author: L15t3Nr
categories:
  - WriteUp
  - Digital Forensics
tags:
  - WriteUp
img_path: /assets/img/FAT32-Access-Time/
permalink: /posts/FAT32-Access-Time/
layout: post
---
# Sunday Funday # 814 - [David Cowen - HECFBlog](https://www.hecfblog.com/2025/04/daily-blog-814-sunday-funday-42025.html)

**Challenge:**
```
FAT32 does not store a time stamp for access dates, it only records the date. However many tools have or have in the past actually treated the zero time entry as a real time entry and adjusted it for time zones. Test your favorite tools such as , ftk imager, xways, axiom, encase, autopsy your choice but you must submit at least two and show if they are correctly handling FAT32 timestamps.
```

This is my first Sunday Funday submission! No expectations of winning a grand prize or anything but just wanting to throw my hat in the ring and explore FAT32. I'm also submitting late due to NCCDC and didn't get around to testing a second tool, so I wouldn't meet the requirements anyways. 

Regardless, I learned quite a bit about FAT32 by doing this challenge: how it's structured, its limitations, and how certain tools might misinterpret the zero time entry and adjust it with the local time zone. 

I tried to make this post as detailed as I could. Mostly because a lot of it is somewhat new to me. I've previously explored JPEGs to manually recover location data, but that's about the extent of my "low-level" manual carving experience. I'm doing a little more of that for this challenge just for fun :) 

---
## **Testing System (Arch Linux (btw)):** 

**uname -a**
![uname](Screenshot_2025-04-22_13-57-15.png)

**cat /etc/os-release**
![os-release](Screenshot_2025-04-22_13-57-59.png)

**date**
![date](Screenshot_2025-04-22_13-55-33.png)

I created a small partition on my host with **20G** of storage and set the type to **EFI System**: 
![disk](Screenshot_2025-04-22_13-59-40.png)
20 gigs is a ton...and I regret this later...

Next I formatted the partition with FAT32, mounted the partition to `/mnt/FAT32`, created a file (**test.txt**) with some "**DATA**", and then un-mounted the partition. 

![actions](Screenshot_2025-04-22_14-04-29.png)

Then I took a *logical* bit-by-bit copy of the partition using the **dd** command: 

![imaging](Screenshot_2025-04-22_14-08-54.png)

The result is a **test.img** file containing the raw data from the FAT32 formatted partition. 

---
## Baseline - RAW Timestamp Data

To get a baseline I figured it would be best to see what timestamp information FAT32 has stored for **test.txt** before testing tools. I ended up doing this after testing the first tool (`istat`). So my command line timestamps aren't aligned with the order I did things.

This is probably more than I need to do, but I enjoy digging in to documentation on new things. 

First I had to find the directory entry for the **test.txt** file to locate the timestamp information. 

I'm using [`fsstat`](https://www.sleuthkit.org/sleuthkit/man/fsstat.html) from [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) to get file system information from **test.img**.

The `fsstat` output below shows some key information for locating the entry. 

![fsstat](Screenshot_2025-04-22_16-11-02.png)

| Label                       | Value                                      |
| --------------------------- | ------------------------------------------ |
| Cluster Size                | 16384 (32 sectors per cluster x 512 bytes) |
| Sector Size                 | 512 bytes                                  |
| Root Directory Cluster      | 2                                          |
| Root Directory Sector Range | 20512 - 20543                              |

I've also used [`fls`](https://www.sleuthkit.org/sleuthkit/man/fls.html) to list file and directory names in the disk image.
![fls](Screenshot_2025-04-24_13-30-57.png)
**test.txt** is the 4th directory entry.

This information can be used to find the offset for the **test.txt** directory entry and then the timestamps. 

Cluster 2 starts at offset 20512. Multiplying this offset by 512 will get the offset of the root directory. 


```bash
echo $((20512 * 512))
10502144
```

The offset I need to check is `10502144`and the 4th directory entry appears to be at the top, which is my **test.txt** file. 

![date-time](Screenshot_2025-04-22_16-09-12.png)

To make sense of the data I followed this [Directory Structure](https://averstak.tripod.com/fatdox/dir.htm) documentation.

Each Directory Entry Structure is 32 bytes long.

The first 32 bytes is a **Long File Name Entry Structure**:
```
4174 0065 0073 0074 002e 000f 008f 7400 7800 7400 0000 ffff ffff 0000 ffff ffff
```

| Offset | Size     | Field                       | Hex Value                     | Info                                           |
| ------ | -------- | --------------------------- | ----------------------------- | ---------------------------------------------- |
| 0x00   | 1 byte   | Sequence Number             | 41                            | A - Long File Name Sequence Number (LFN)       |
| 0x01   | 10 bytes | Name Part 1                 | 74 002e 000f 00               | test. - 0x00 are null values                   |
| 0x0B   | 1 byte   | Attributes                  | 0f                            | LFN                                            |
| 0x0C   | 1 byte   | Type                        | 00                            |                                                |
| 0x0D   | 1 byte   | Checksum of Short File Name | 8f                            | 143 - Checksum value (I don't understand this) |
| 0x0E   | 12 bytes | Name Part 2                 | 7400 7800 7400 0000 ffff ffff | txt - the file extension                       |
| 0x1A   | 2 bytes  | First cluster               | 0000 ffff                     | 0                                              |
| 0x1C   | 4 bytes  | Name Part 3                 | ffff                          | Padding                                        |

Basically, this first 32 byte entry is for the filename. 

The next 32 bytes is a **Standard 8.3 Directory Entry Structure**  (Time and Date):
```
5445 5354 2020 2020 5458 5420 008b 7890 965a 965a 0000 7890 965a 0300 0500 0000
```

| Offset | Size     | Field                   | Hex Value                      | Value                                                          |
| ------ | -------- | ----------------------- | ------------------------------ | -------------------------------------------------------------- |
| 0x00   | 11 bytes | Filename (8.3 Format)   | 5445 5354 2020 2020 5458 54    | TEST    TXT                                                    |
| 0x0B   | 1 byte   | Attributes              | 20                             | Archive Bit Set                                                |
| 0x0C   | 1 byte   | Reserved                | 00                             | Always Zero                                                    |
| 0x0D   | 1 byte   | Creation Time Tenths    | 8b                             | 139 - Milliseconds                                             |
| 0x0E   | 2 bytes  | Creation Time           | 7890->9078 <br>(Little Endian) | 10010->18<br>000011->3<br>11000->24\*2=48<br>**18:03:48**      |
| 0x10   | 2 bytes  | Creation Date           | 965a->5a96 <br>(Little Endian) | 0101101->1980+45=2025<br>0100->4<br>10110->22<br>**4-22-2025** |
| 0x12   | 2 bytes  | Last Access Date        | 965a->5a96<br>(Little Endian)  | 0101101->1980+45=2025<br>0100->4<br>10110->22<br>**4-22-2024** |
| 0x14   | 2 bytes  | High 16 Bits of Cluster | 0000                           | -                                                              |
| 0x16   | 2 bytes  | Last Modified Time      | 7890->9078<br>(Little Endian)  | 10010->18<br>000011->3<br>11000->24\*2=48<br>**18:03:48**      |
| 0x18   | 2 bytes  | Last Modified Date      | 965a->5a96<br>(Little Endian)  | 0101101->1980+45=2025<br>0100->4<br>10110->22<br>**4-22-2025** |
| 0x1A   | 2 bytes  | Low 16 Bits of Cluster  | 0300                           | -                                                              |
| 0x1C   | 4 bytes  | File Size               | 0500 0000                      | 1280 bytes                                                     |

The time and date information is in this second entry and I was able to convert the bytes to dates and timestamps from the documentation. 

| Field              | Value     |
| ------------------ | --------- |
| Creation Time      | 18:03:48  |
| Creation Date      | 4-22-2025 |
| Last Access Date   | 4-22-2025 |
| Last Modified Time | 18:03:48  |
| Last Modified Date | 4-22-2025 |

FAT32 uses localtime for its timestamps, however, my system clock is set to UTC. So while my localtime is actually 14:03:48 EDT at the time I made the **test.txt** file, FAT32 used my system clock and the timestamps are UTC there.

Now I know what FAT32 recorded for time and date and I can compare it to the tools that I'm going to test.

---

## Tool Test 1 - istat (TheSleuthKit)
The first tool I tested was [`istat`](https://www.sleuthkit.org/sleuthkit/man/istat.html) from the [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/).

![istat](Screenshot_2025-04-22_14-16-23.png)
*You might notice the time is now 14:16:06 - I actually did this part before digging in to FAT32 manually.*

**The Sleuth Kit version is 4.13.0**

I used the `fls` tool from The Sleuth Kit to get the test file's inode number. However, I learned that FAT32 does not have an "inode table", but has "directory entries" in a directory entry table (structure). The number it identified for my **test.txt** file was 4.

Just below the `fls` output is the `istat` command output. `istat` uses the Directory Entry number (4) to check the 4th directory entry.

![fls-istat](Screenshot_2025-04-22_14-18-32.png)

The output from `istat` appears to accurately interpret the Accessed zero time entry.

If it had adjusted for the time zone, i'd have expected to see the Accessed Timestamp to be 20:00:00 for the previous day since I am UTC-4.

---
## References
 [David Cowen - HECFBlog](https://www.hecfblog.com/2025/04/daily-blog-814-sunday-funday-42025.html)
[The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/)
[`istat`](https://www.sleuthkit.org/sleuthkit/man/istat.html)
[Directory Structure](https://averstak.tripod.com/fatdox/dir.htm)
[`fls`](https://www.sleuthkit.org/sleuthkit/man/fls.html)

