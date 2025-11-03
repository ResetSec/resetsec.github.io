const CTFTimeTeamID = 266022;
const CTFTimeURL = `https://ctftime.org/team/${CTFTimeTeamID}`;

const teamMembers = [
  {
    name: "makid3r",
    leader: true, // add misc category
    tags: ["web", "forensics", "misc", "pwn", "mobile"],
    bio: "i like cyberpunk (and CS) (and also pizza, [and C.C])",
    socials: {
      Blog: "https://makider.me",
      GitHub: "https://github.com/N1kkogg",
    },
  },
  {
    name: "VulnX",
    tags: ["pwn", "reverse engineering", "mobile", "forensics"],
    bio: "pwning stuff...\nPresident of Crypto club @ResetSec",
    socials: {
      Website: "https://vulnx.github.io",
      GitHub: "https://github.com/VulnX",
      YouTube: "https://youtube.com/@thevulnx",
    },
  },
  {
    name: "0x42",
    tags: ["osint", "forensics", "hardware"],
    bio: "The web whispers. I listen, uncovering patterns where others see noise.",
    socials: {
      GitHub: "https://github.com/TimelessFez",
    },
  },
  {
    name: "ap425q",
    tags: ["pwn", "reverse engineering"],
    bio: "Security Researcher",
    socials: {
      Blog: "https://ap425q.github.io/",
      GitHub: "https://github.com/ap425q",
    },
  },
  {
    name: "calmred",
    tags: ["forensics"],
    bio: "TBD",
  },
  {
    name: "Kibov",
    tags: ["web", "reverse engineering"],
    bio: "Sometimes I know what I'm doing",
    socials: {
      Blog: "https://kibov.pl/posts/",
    },
  },
  {
    name: "m3m0rydmp",
    tags: ["web", "osint"],
    bio: "TBD",
  },
  {
    name: "Madrat_0",
    tags: ["crypto", "web"],
    bio: "Crypto. Chaos. No sleep.",
    socials: {
      GitHub: "https://github.com/Adrito-M",
      CodeForces: "https://codeforces.com/profile/MadRat_0",
    },
  },
];

const formerMembers = [
    {
        name: "AntennaeVY",
        tags: [],
        bio: "",
    },
    {
        name: "Brine",
        tags: [],
        bio: "",
    },
    {
        name: "calx",
        tags: [],
        bio: "",
    },
    {
        name: "daVinci",
        tags: [],
        bio: "",
    },
    {
        name: "FIN",
        tags: [],
        bio: "",
    },
    {
        name: "gexxr",
        tags: [],
        bio: "",
    },
    {
        name: "greysneakthief",
        tags: [],
        bio: "",
    },
    {
        name: "Ivan Nikolskiy",
        tags: [],
        bio: "",
    },
    {
        name: "lh0ax",
        tags: [],
        bio: "",
    },
    {
        name: "ol3livi0n",
        tags: ["web", "blockchain"],
        bio: "Spidering the web...",
        socials: {
            "GitHub": "https://github.com/OI3livion",
            "X": "https://x.com/ol3livi0n",
        }
    },
    {
        name: "seaglade",
        tags: ["reverse engineering", "web", "forensics", "osint"],
        bio: "maybe someday i'll be half-decent at rev and binex... o_o",
        socials: {
            "Website": "https://seaglade.dev",
            "GitHub": "https://github.com/seaglade",
        },
    },
    {
        name: "Spaced out Rexy",
        tags: [],
        bio: "",
    },
    {
      name: "Spaced out Rexy",
      tags: [],
      bio: "",
    },
    {
      name: "Tr1dent",
      tags: [],
      bio: "",
    },
    {
      name: "xxaxaaa",
      tags: [],
      bio: "",
    }
];

function addMembers(where, members) {
  const table = document.querySelector(where);
  if (table === null) {
    console.error("Failed to insert members table. Cannot find <table> tag");
    return;
  }
  const colGroup = document.createElement("colgroup");
  const colLeft = document.createElement("col");
  const colRight = document.createElement("col");
  colLeft.style.width = "25%";
  colRight.style.width = "75%";
  colGroup.appendChild(colLeft);
  colGroup.appendChild(colRight);
  table.appendChild(colGroup);
  members.forEach((member) => {
    const tr = document.createElement("tr");
    const tdImage = document.createElement("td");
    const img = document.createElement("img");
    const tdMemberDescription = document.createElement("td");
    const divMemberDescription = document.createElement("div");
    const divTags = document.createElement("div");
    const pName = document.createElement("p");
    const divBio = document.createElement("div");

    img.src = window.location.href + `/assets/profile/${member.name}.webp`;
    img.alt = member.name;
    img.className = "member-pfp";
    tdImage.appendChild(img);
    divMemberDescription.className = "member-description";
    divTags.className = "tags";
    member.tags.forEach((tag) => {
      const spanTag = document.createElement("span");
      spanTag.className = "tag";
      spanTag.setAttribute("data-tag", tag);
      divTags.appendChild(spanTag);
    });
    pName.className = "name";
    pName.textContent = member.name;
    if (member.leader === true) {
      pName.setAttribute("data-leader", "true");
    }
    divBio.className = "bio";
    member.bio.split("\n").forEach((line) => {
      const spanLine = document.createElement("span");
      spanLine.textContent = line;
      divBio.appendChild(spanLine);
    });
    if (member.socials !== undefined) {
      const ul = document.createElement("ul");
      for (const key in member.socials) {
        if (member.socials.hasOwnProperty(key)) {
          const what = key;
          const link = member.socials[what];
          const li = document.createElement("li");
          const aLink = document.createElement("a");
          aLink.href = link;
          aLink.target = "_blank";
          aLink.textContent = what;
          li.appendChild(aLink);
          ul.appendChild(li);
        }
      }
      divBio.appendChild(ul);
    }
    divMemberDescription.appendChild(divTags);
    divMemberDescription.appendChild(pName);
    divMemberDescription.appendChild(divBio);
    tdMemberDescription.appendChild(divMemberDescription);
    tr.appendChild(tdImage);
    tr.appendChild(tdMemberDescription);
    table.appendChild(tr);
  });
}

async function getTeamStats() {
  const res = await fetch(window.location.href + "/stats.json");
  const text = await res.text();
  const stats = JSON.parse(text);
  return stats;
}

/**
 * Calculates the CTF score based on the points and the rank of the team.
 *
 * The score is computed as the ratio of points to place. This ensures that the
 * CTF rank is not determined solely by the team's place (which could be
 * influenced by the number of teams participating) or the points (which could
 * depend on how highly rated the CTF event is). Instead, both factors are
 * considered simultaneously to give a more balanced score.
 */
function getCTFScore(ctf) {
  const score = Number(ctf.points) / Number(ctf.place);
  console.log(ctf, "score:", score);
  return score;
}

function addTeamStats() {
  // config variables
  const max_ctfs = 5; // Maximum number of CTFs to display from each year

  const statsPromise = getTeamStats();

  const table = document.querySelector(".team-stats");
  if (table === null) {
    console.error("Failed to insert members table. Cannot find <table> tag");
  }

  const colGroup = document.createElement("colgroup");
  const col1 = document.createElement("col");
  const col2 = document.createElement("col");
  const col3 = document.createElement("col");
  col1.style.width = "20%";
  col2.style.width = "20%";
  col3.style.width = "60%";
  colGroup.appendChild(col1);
  colGroup.appendChild(col2);
  colGroup.appendChild(col3);
  table.appendChild(colGroup);

  const trHeading = document.createElement("tr");
  const tdHeadingYear = document.createElement("td");
  const tdHeadingRank = document.createElement("td");
  const tdHeadingCTF = document.createElement("td");
  tdHeadingYear.innerText = "Year";
  tdHeadingRank.innerText = "Rank";
  tdHeadingCTF.innerText = "CTF";
  trHeading.appendChild(tdHeadingYear);
  trHeading.appendChild(tdHeadingRank);
  trHeading.appendChild(tdHeadingCTF);
  table.appendChild(trHeading);

  statsPromise.then((stats) =>
    stats.forEach((record) => {
      const ctfs = record.ctfs
        .sort((a, b) => getCTFScore(b) - getCTFScore(a))
        .slice(0, max_ctfs);

      ctfs.forEach((ctf, i) => {
        const tr = document.createElement("tr");
        const tdRank = document.createElement("td");
        const tdCTF = document.createElement("td");
        if (i == 0) {
          const tdYear = document.createElement("td");
          tdYear.innerText = record.year;
          tdYear.rowSpan = max_ctfs;
          tr.appendChild(tdYear);
        }
        tdRank.innerText = ctf.place;
        tdCTF.innerText = ctf.event;
        tr.appendChild(tdRank);
        tr.appendChild(tdCTF);
        table.appendChild(tr);
      });
    })
  );
}

document.querySelector(".terminal-btn").addEventListener("click", () => {
  window.location.href += "reset-console/";
});

function showSplashAnimation() {
  // config variables
  const repeat = 3;
  const animationSpeed = 30; // (in milliseconds)

  const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const title = document.querySelector(".splash-title");
  const titleString = title.textContent;
  let iterations = 0;
  const interval = setInterval(() => {
    title.textContent = title.textContent
      .split("")
      .map((_letter, index) => {
        if (index < iterations) {
          return titleString[index];
        }
        return letters[Math.floor(Math.random() * letters.length)];
      })
      .join("");
    iterations += 1 / repeat;
    if (titleString.length < iterations) {
      clearInterval(interval);
      hideSplashScreen();
    }
  }, animationSpeed);

  function hideSplashScreen() {
    // config variables (in milliseconds)
    const delay = 750;
    const transitionSpeed = 300;

    setTimeout(() => {
      const splashScreen = document.querySelector(".splash-screen");
      splashScreen.style.transition = `${transitionSpeed / 1000}s`;
      splashScreen.style.opacity = 0;
      setTimeout(() => {
        splashScreen.style.display = "none";
      }, transitionSpeed);
    }, delay);
  }
}

showSplashAnimation();
addMembers(".active-members", teamMembers);
addMembers(".former-members", formerMembers);
addTeamStats();
