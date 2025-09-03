import argparse
import requests
from bs4 import BeautifulSoup
from PIL import Image
from PIL.ExifTags import TAGS
import io

def get_exif_data(image_url):
    """
    Downloads an image from a URL and extracts its EXIF metadata.
    Returns a dictionary of EXIF data or None if the image can't be processed.
    """
    exif_data = {}
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(image_url, timeout=10, headers=headers)
        response.raise_for_status()

        img = Image.open(io.BytesIO(response.content))

        info = img._getexif()
        if info:
            for tag, value in info.items():
                decoded_tag = TAGS.get(tag, tag)
                # To handle GPSInfo, which is a dict itself
                if decoded_tag == "GPSInfo":
                    gps_data = {}
                    for t in value:
                        gps_decoded = TAGS.get(t, t)
                        gps_data[gps_decoded] = value[t]
                    exif_data[decoded_tag] = gps_data
                else:
                    exif_data[decoded_tag] = value
        return exif_data
    except requests.RequestException:
        return None  # Indicates failure to download or access
    except Exception:
        return {}    # Indicates image was processed but no EXIF data was found

def scrape_github_profile(username):
    """
    Scrapes a GitHub profile for public information and analyzes the avatar.
    This function serves as a template for deep analysis on a single platform.
    """
    url = f"https://github.com/{username}"
    profile_data = {"platform": "GitHub", "url": url, "found": False}
    print(f"[*] فحص GitHub للمستخدم '{username}'...")

    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"  [-] لم يتم العثور على ملف شخصي على GitHub (الحالة: {response.status_code}).")
            return profile_data

        profile_data["found"] = True
        soup = BeautifulSoup(response.content, 'html.parser')

        name_tag = soup.find('span', class_='p-name')
        profile_data['name'] = name_tag.text.strip() if name_tag else "غير متاح"

        bio_tag = soup.find('div', class_='p-note')
        profile_data['bio'] = bio_tag.text.strip() if bio_tag else "غير متاح"

        avatar_tag = soup.find('img', class_='avatar-user')
        if avatar_tag and avatar_tag.get('src'):
            avatar_url = avatar_tag['src']
            profile_data['avatar_url'] = avatar_url

            print(f"    [*] تحليل صورة الملف الشخصي للبيانات الوصفية (EXIF)...")
            exif = get_exif_data(avatar_url)
            if exif is None:
                profile_data['exif_status'] = "تعذر تنزيل الصورة."
            elif exif:
                profile_data['exif_data'] = exif
            else:
                profile_data['exif_status'] = "لم يتم العثور على بيانات EXIF."

    except requests.RequestException as e:
        print(f"  [!] خطأ في الشبكة أثناء فحص GitHub: {e}")

    return profile_data

def print_profile_data(data):
    """Prints the scraped profile data in a structured format."""
    if not data.get("found"):
        return

    print(f"\n--- [ نتائج {data['platform']} ] ---")
    print(f"  [+] رابط الملف الشخصي: {data['url']}")
    print(f"    - الاسم: {data.get('name', 'غير متاح')}")
    print(f"    - السيرة الذاتية: {data.get('bio', 'غير متاح')}")

    if data.get('avatar_url'):
        print(f"    - رابط الصورة: {data.get('avatar_url')}")

    if data.get('exif_status'):
        print(f"    - حالة EXIF: {data.get('exif_status')}")

    if data.get('exif_data'):
        print("    - بيانات EXIF:")
        for key, val in data['exif_data'].items():
            if isinstance(val, bytes) and len(val) > 64:
                val = f"<{len(val)} bytes of data>"
            print(f"      - {key}: {val}")
    print("-" * 30)

def main():
    """
    Main function to drive the social media analysis.
    """
    parser = argparse.ArgumentParser(
        description="محلل وسائط اجتماعية متقدم للبحث عن أسماء المستخدمين وتحليل ملفاتهم الشخصية.",
        epilog="مثال: python social_media_analyzer.py 'torvalds'"
    )
    parser.add_argument("username", help="اسم المستخدم للبحث عنه.")
    args = parser.parse_args()

    print(f"[+] بدء التحليل المتقدم لاسم المستخدم: '{args.username}'")

    # As a proof of concept, we only analyze GitHub for now.
    # This can be expanded with more functions for other platforms.
    github_data = scrape_github_profile(args.username)
    print_profile_data(github_data)

    print("\n[+] اكتمل التحليل.")

if __name__ == "__main__":
    main()
