import requests
from bs4 import BeautifulSoup
import json


def get_team_stats(ctf_time_url):
    response = requests.get(ctf_time_url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    years = soup.select(".container .tab-content .tab-pane[id^='rating_']")
    stats = []
    for year in years:
        year_string = year["id"].split("rating_")[1]
        table = year.find("table")
        rows = table.find_all("tr")[1:]
        ctfs = []
        for row in rows:
            cols = row.find_all("td")
            ctfs.append(
                {
                    "place": cols[1].text.strip(),
                    "event": cols[2].text.strip(),
                    "points": cols[4].text.strip(),
                }
            )
        stats.append({"year": year_string, "ctfs": ctfs})
    return stats


CTFTimeTeamID = 266022
CTFTimeURL = f"https://ctftime.org/team/{CTFTimeTeamID}"
team_stats = get_team_stats(CTFTimeURL)

with open("stats.json", "w") as f:
    json.dump(team_stats, f)
