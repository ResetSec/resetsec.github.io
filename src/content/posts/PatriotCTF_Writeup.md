---
title: PatriotCTF 2025 OSINT writeups
event: "PatriotCTF 2025"
category: "OSINT"
description: Follow along as we solve the two main OSINT tasks of PatriotCTF 2025.
date: 2025-11-03
tags:
  - ctf
  - osint
image: /assets/blog/nova/osint-patriotctf.png
author:
  - iiNovaCore
---

# intro

Hey! I was able to compete with some of the wonderful people at ResetSec for this competition, and here's how I was able to solve 2 OSINT challenges from start to finish, specifically ones that others seemed to have a bit of trouble with.

# osint/Kittiez!!!!!
**Author: vWing**

This challenge gives you a text file with the following.

```
I lost it all in one bad tick-
my feline Vault, gone *way* too quick.
A virus on my janky 'puter
went boom and turned my cats to neuter.

I had so many cats in store,
but one's the one my heart longs for.
If I could see that pic again,
my nine lives might come back to ten.

For "maximum security" flair,
I hashed each cat with loving care.
Couldn't back up the pics themselves-
the feds would sniff them off my shelves.

So now I search through bits and trash
for just one sacred, purring stash.
If you can find that photo, friend,
my broken heart might almost mend. <3

The md5 file hash of my beloved picture is:

9c5ca692da8d6e489beecd5b448ddb35
pctf{Shoutout_To_Silly_Cats}
(  The flag is the text in the image - case insensitive. Replace spaces with underscores, i.e. pctf{I_Love_Kitties!}  )
```

This task involves finding an image with a file hash. At the time, my first instinct was to throw it in Virustotal, however, at the time there was no results. However, as of now, this is no longer the case.

https://www.virustotal.com/gui/file/3bb3fbf6c9073c52ab5337ae7f1813495028cf28a24c0005ff51367fd0a7cc0f/community

![virustotal-kittiez.png](/assets/blog/nova/virustotal-kittiez.png)

That file name will be the file name later, but this is the result of another competitor. If you are really curious on what that pastebin says, it says the following decoded as hex.

```
I would like to say that this challenge is 10% Misc, 90% GuessINT, and 0% OSINT. Also, 01001110 01100101 01110110 01100101 01110010 00100000 01000111 01101111 01101110 01101110 01100001 00100000 01000111 01101001 01110110 01100101 00100000 01011001 01101111 01110101 00100000 01010101 01110000 00100001
```

The binary is just a rick roll.

...so what now?

Well, if you look in the Discord for the competition, the author posted a hint.

![vwing-katz-hint.png](/assets/blog/nova/vwing-katz-hint.png)

You can either find it from this, or use some elite ball knowledge to figure out that VX-Underground has a large archive of cat images.

![cat-archive-for-kittiez.png](/assets/blog/nova/cat-archive-for-kittiez.png)

(https://vx-underground.org/Archive/Cat%20Picture%20Collection)

Downloading all of these allows you to get the MD5 file checksum of all of the attached files, which gives you the right file, with the file name as before.

```bash
find . -type f -exec md5sum "{}" \; | grep -i "9c5ca692da8d6e489beecd5b448ddb35"
./Cats.00003/3bb3fbf6c9073c52ab5337ae7f1813495028cf28a24c0005ff51367fd0a7cc0f.jpg
```
(paraphrasing as I closed my terminal)

This allows you to open the image, which is the following.

![shoutout-to-silly-cats.png](/assets/blog/nova/shoutout-to-silly-cats.png)
(3bb3fbf6c9073c52ab5337ae7f1813495028cf28a24c0005ff51367fd0a7cc0f.jpg)
### Flag: pctf{shoutout_to_silly_cats}

# **osint/Crazy Night out**
**Author: Neil Sharma**

This challenge gives you a very basic prompt. Find the cities/towns in Northern Virginia that these images were taken at.

The images are attached below, and the ones that we used for actual solutions will be used in the blog.

# Location #1

![skyzone-crazynightout.jpg](/assets/blog/nova/skyzone-crazynightout.jpg)

This one was by far the easiest. Googling "sky socks" shows results for Sky Zone, a trampoline park franchise popular in America. By the state of the Sky Zone here, we can tell it hasn't been open for quite a while. 

https://patch.com/virginia/ashburn/skyzone-trampoline-park-closes-cascades-marketplace

Well, there's an abandoned Sky Zone in Sterling, Virginia, which is northern Virginia. This is very clearly our match here.

# Location #2

![skyview-crazynightout.jpg](/assets/blog/nova/skyview-crazynightout.jpg)
This one, though very small and blurry, shows a Target and CVS in the same building. It's also very obviously a big area, most likely around Washington DC. Since the challenge creators are in Fairfax county, we can also take a good guess it's in Fairfax County. If you wanna go the manual route, you can use Target's store directory to look at all of the Targets in Virginia.

You can also just search "Target" while looking over Virginia, and find an exact match of the building.

![target-reston-crazynightout.png](/assets/blog/nova/target-reston-crazynightout.png)

This is the Reston, Virginia Target, and it matches with the prior picture. You can confirm by looking at other buildings in the area.

# Location #3

This one has two images necessary.

![iclliquidation-crazynightout.jpg](/assets/blog/nova/iclliquidation-crazynightout.jpg)

![atrium-crazynightout.jpg](/assets/blog/nova/atrium-crazynightout.jpg)

The challenge author previously stated that he did not take all of these pictures himself, this will be important in a moment.

ICL's paper is where we will start. ICL has two phone numbers there, but none of them are in the Northern Virginia area. They are known for hotel and resort liquidation. Going to their website, we can search for all of their prior hotels they have liquidated.

In one of the other pictures, we can also see this carpet, which we can see in the carpet in JFK's Sheraton in NYC.

![carpetpattern-crazynightout.png](/assets/blog/nova/carpetpattern-crazynightout.png)

![jfksheraton-crazynightout.png](/assets/blog/nova/jfksheraton-crazynightout.png)

However, that's not Northern Virginia. Looking on ICL's page for Sheratons, we can find the exact hotel at https://www.iclsales.com/sale-listing/sheraton-tysons-landing/. Now, for the nail in the coffin, there's a picture on Yelp about the hotel as well.

![sheratonyelpimage-crazynightout.png](/assets/blog/nova/sheratonyelpimage-crazynightout.png)

This confirms the building as being the Tysons Sheraton. The pillars are an exact match, and are placed very similarly, and there's another picture with the atrium

![sheratongoogleimage-crazynightout.png](/assets/blog/nova/sheratongoogleimage-crazynightout.png)


## Flag: pctf{Sterling_Reston_Tysons}

# epilogue

That's all the OSINT I'm covering for this writeup, thank you to the organizers over at GMU!

-iiNovaCore
