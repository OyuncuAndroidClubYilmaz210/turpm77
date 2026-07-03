import discord
from discord.ext import commands
from bot_token import TOKEN
import requests
import scipy.io.wavfile as wav
import speech_recognition as sr
import sounddevice as sd
import asyncio
import random
import io
from gtts import gTTS
from google import genai

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# 🔑 API Anahtarların
ai_client = genai.Client(api_key="AQ.Ab8RN6LoNELwvqNmdJOdGqXhD9l4-abmhOL_yNepBKDqrf9HWQ")
VIRUSTOTAL_API_KEY = "f5c6a33961a1d14582e0db0e3c90d2fa667b469365deb24e2562f95b69316812"  # 🔒 API Anahtarın başarıyla eklendi!

# --- OYUN VERİ TABANI (Hafızada Tutulur, Bot Kapanınca Sıfırlanır) ---
CLICKER_DATA = {} # Kullanıcıların clicker verileri
RPG_DATA = {}     # Kullanıcıların aktif RPG hikayeleri

LANGUAGES = {
    'es': 'ispanyolca', 'ru': 'rusça', 'en': 'ingilizce', 'pt': 'portekizce',
    'id': 'endonezya', 'pl': 'lehçe', 'it': 'italyanca', 'tr': 'türkçe',
    'de': 'almanca', 'fr': 'fransızca', 'nl': 'felemenkçe', 'sv': 'isveççe',
    'no': 'norveççe', 'da': 'danca', 'fi': 'fince', 'cs': 'çekçe',
    'sk': 'slovakça', 'hu': 'macarca', 'ro': 'romence', 'el': 'yunanca',
    'uk': 'ukraynaca', 'bg': 'bulgarca', 'hr': 'hırvatça', 'sr': 'sırpça',
    'sl': 'slovence', 'lt': 'litvanca', 'lv': 'letonca', 'et': 'estonca',
    'ar': 'arapça', 'fa': 'farsça', 'he': 'ibranice', 'hi': 'hintçe',
    'ur': 'urduca', 'bn': 'bengalce', 'ta': 'tamilce', 'te': 'telugu',
    'ml': 'malayalamca', 'kn': 'kannada', 'zh-cn': 'çince'
}

TURKISH_WORDS = [
    "kitap", "araba", "su", "kedi", "köpek", "merhaba", "güneş", "ay", "bilgisayar", 
    "okul", "öğretmen", "elma", "kırmızı", "büyük", "küçük", "ev", "arkadaş", "zaman",
    "göz", "yürek", "çocuk", "deniz", "gökyüzü", "çiçek", "kuş", "yeşil", "mavi"
]


# 🛡️ TAMAMEN ESNEKLEŞTİRİLMİŞ ANTİVİRÜS: LİNK VE DOSYA TARAMA KOMUTU
@bot.command()
async def scan(ctx, *, url: str = None):
    # Kontrol 1: Eklenmiş dosyaları listeye alıyoruz
    attachments = ctx.message.attachments
    
    # Eğer attachments listesi boşsa ama atılan mesaj metninde gizli bir Discord CDN bağlantısı varsa yakala
    if not attachments and url and ("cdn.discordapp.com" in url or "media.discordapp.net" in url):
        pass

    if attachments:
        attachment = attachments[0]
        mesaj = await ctx.send(f"📂 `{attachment.filename}` dosyası VirusTotal laboratuvarına yükleniyor ve taranıyor... Lütfen bekleyin.")
        
        try:
            # Dosyayı Discord sunucularından indirip hafızaya (RAM) alıyoruz
            file_bytes = await attachment.read()
            files = {"file": (attachment.filename, file_bytes)}
            
            # VirusTotal dosya yükleme API'si
            vt_upload_url = "https://www.virustotal.com/api/v3/files"
            headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
            
            # Dosyayı yüklüyoruz
            response = await asyncio.to_thread(requests.post, vt_upload_url, files=files, headers=headers)
            
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                await asyncio.sleep(6)  # Detaylı analiz için bekleme süresini 6 saniye yaptık
                
                # Sonuç raporunu çekiyoruz
                report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                report_response = await asyncio.to_thread(requests.get, report_url, headers=headers)
                stats = report_response.json()["data"]["attributes"]["stats"]
                
                zararli = stats["malicious"]
                supheli = stats["suspicious"]
                
                if zararli > 0 or supheli > 0:
                    await mesaj.edit(content=f"🚨 **TEHLİKELİ DOSYA TESPİT EDİLDİ!**\n> 👤 **Yükleyen:** {ctx.author.mention}\n> 📂 **Dosya Adı:** `{attachment.filename}`\n> ❌ **Tehdit Sayısı:** `{zararli}` antivirüs virüslü buldu!\n\n🛡️ *Güvenlik gereği bu dosya sunucudan imha ediliyor...*")
                    
                    # 🛑 VİRÜSLÜ DOSYAYI (MESAJI) SUNUCUDAN SİLİYORUZ!
                    await ctx.message.delete()
                else:
                    await mesaj.edit(content=f"✅ **Dosya Temiz!**\n> 📂 **Dosya Adı:** `{attachment.filename}`\n> 🛡️ Yapılan detaylı analizde hiçbir virüs veya tehdit bulunamadı. Güvenle indirebilirsiniz.")
            else:
                await mesaj.edit(content="❌ Dosya VirusTotal sunucularına yüklenirken bir hata oluştu. Lütfen 21. satırdaki API anahtarınızı kontrol edin.")
        except Exception as e:
            print(f"Dosya tarama hatası: {e}")
            await mesaj.edit(content="❌ Teknik bir hata nedeniyle dosya taraması başarısız oldu.")
        return

    # Kontrol 2: Kullanıcı dosya atmadı ama sadece normal bir link taratmak istiyorsa (!scan https://...)
    if url is not None:
        mesaj = await ctx.send("🔍 *Bağlantı (Link) antivirüs motorlarıyla taranıyor, lütfen bekleyin...*")
        vt_url = "https://www.virustotal.com/api/v3/urls"
        payload = f"url={requests.utils.quote(url)}"
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY,
            "content-type": "application/x-www-form-urlencoded"
        }
        try:
            response = await asyncio.to_thread(requests.post, vt_url, data=payload, headers=headers)
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                await asyncio.sleep(4)
                report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                report_response = await asyncio.to_thread(requests.get, report_url, headers=headers)
                stats = report_response.json()["data"]["attributes"]["stats"]
                
                zararli = stats["malicious"]
                supheli = stats["suspicious"]
                temiz = stats["harmless"]

                if zararli > 0 or supheli > 0:
                    await mesaj.edit(content=f"⚠️ **TEHLİKELİ LİNK TESPİT EDİLDİ!**\n> 🌐 **Link:** `{url}`\n> 🛑 **Tehdit:** `{zararli}` antivirüs zararlı buldu!\n\n*Lütfen bu bağlantıya tıklamayın!*")
                else:
                    await mesaj.edit(content=f"✅ **Bağlantı Güvenli!**\n> 🌐 **Link:** `{url}`\n> 🛡️ `{temiz}` farklı motor temiz raporu verdi.")
            else:
                await mesaj.edit(content="❌ Antivirüs servisine bağlanılamadı.")
        except Exception as e:
            await mesaj.edit(content="❌ Tarama yapılamadı.")
        return

    # Kontrol 3: Kullanıcı boş komut gönderdiyse
    await ctx.send("❌ Lütfen taratmak için ya bir dosya yükleyip açıklama kısmına `!scan` yazın ya da bir link belirtin! **Örnek:** `!scan https://google.com`")


# 🕹️ OYUN 1: CLICKER (TIKLAMA OYUNU)
@bot.command()
async def clicker(ctx):
    user_id = ctx.author.id
    if user_id not in CLICKER_DATA:
        CLICKER_DATA[user_id] = {"points": 0, "workers": 0}

    bonus = CLICKER_DATA[user_id]["workers"] * 2
    gained = 1 + bonus
    CLICKER_DATA[user_id]["points"] += gained

    puan = CLICKER_DATA[user_id]["points"]
    isci = CLICKER_DATA[user_id]["workers"]
    
    await ctx.send(f"⛏️ {ctx.author.mention} kazmayı vurdu ve **+{gained} puan** kazandı!\n💰 **Toplam Puanın:** `{puan}`\n🤖 **Otomatik İşçi Sayın:** `{isci}` *(İşçi almak için `!buy` yazabilirsin!)*")

@bot.command()
async def buy(ctx):
    user_id = ctx.author.id
    if user_id not in CLICKER_DATA:
        CLICKER_DATA[user_id] = {"points": 0, "workers": 0}

    cost = 15 + (CLICKER_DATA[user_id]["workers"] * 10)

    if CLICKER_DATA[user_id]["points"] >= cost:
        CLICKER_DATA[user_id]["points"] -= cost
        CLICKER_DATA[user_id]["workers"] += 1
        await ctx.send(f"🤖 🎉 {ctx.author.mention}, **{cost} puan** ödeyerek yeni bir otomatik işçi satın aldı! Artık tıklama başına daha çok puan kazanacaksın.")
    else:
        await ctx.send(f"❌ {ctx.author.mention}, yeterli puanın yok! Gerekli puan: `{cost}`. Şu anki puanın: `{CLICKER_DATA[user_id]['points']}`")


# 🧙 OYUN 2: YAPAY ZEKA DESTEKLİ RPG MACERA OYUNU
@bot.command()
async def adventure(ctx, *, karar: str = None):
    user_id = ctx.author.id
    
    if karar is None or user_id not in RPG_DATA:
        await ctx.send("⚔️ **Yapay Zeka RPG Macerası Başlıyor...**\n*Gemini senin için fantastik bir dünya hazırlıyor...*")
        
        def start_story():
            prompt = "Bana Discord üzerinden oynanacak interaktif, fantastik bir rol yapma oyunu (RPG) başlangıcı yaz. Kısa olsun (en fazla 3-4 cümle). Hikayenin sonunda oyuncuya net bir şekilde seçebileceği kısa A, B ve C seçenekleri sun. Türkçe olsun."
            response = ai_client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
            return response.text

        try:
            story = await asyncio.to_thread(start_story)
            RPG_DATA[user_id] = [ {"role": "model", "parts": [{"text": story}]} ]
            await ctx.send(f"📖 {ctx.author.mention}, hikayen başladı:\n\n{story}\n\n*İlerlemek için `!adventure <seçeneğin>` yazabilirsin!*")
        except Exception as e:
            await ctx.send("❌ Hikaye başlatılırken bir sorun oluştu.")
        return

    await ctx.send("🔄 *Seçimin doğrultusunda kaderin yazılıyor...*")
    RPG_DATA[user_id].append({"role": "user", "parts": [{"text": karar}]})

    def continue_story():
        response = ai_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=RPG_DATA[user_id]
        )
        return response.text

    try:
        next_story = await asyncio.to_thread(continue_story)
        RPG_DATA[user_id].append({"role": "model", "parts": [{"text": next_story}]})
        await ctx.send(f"🔮 {ctx.author.mention}:\n\n{next_story}")
    except Exception as e:
        await ctx.send("❌ Kaderin belirlenirken bir hata oluştu.")


# --- ESKİ KOMUTLAR (Sohbet, Çeviri, Resim, Ses, Hava Durumu) ---

@bot.command()
async def speak(ctx, *, metin: str = None):
    if metin is None:
        await ctx.send("❌ Lütfen sese dönüştürmemi istediğin bir metin yaz!")
        return
    mesaj = await ctx.send("🎙️ *Ses dosyası oluşturuluyor...*")
    def generate_tts():
        tts = gTTS(text=metin, lang='tr', slow=False)
        fp = io.BytesIO()
        tts.write_to_fp(fp)
        fp.seek(0)
        return fp
    try:
        audio_fp = await asyncio.to_thread(generate_tts)
        audio_file = discord.File(audio_fp, filename="ses.mp3")
        await mesaj.delete()
        await ctx.send(content=f"🔊 {ctx.author.mention}:", file=audio_file)
    except Exception as e:
        await mesaj.edit(content="❌ Ses oluşturulamadı.")

@bot.command()
async def draw(ctx, *, prompt: str = None):
    if prompt is None:
        await ctx.send("❌ Lütfen çizmemi istediğin bir şey yaz!")
        return
    mesaj = await ctx.send("🎨 *Resmini çiziyorum...*")
    def download_image():
        formatted_prompt = requests.utils.quote(prompt)
        url = f"https://image.pollinations.ai/p/{formatted_prompt}?width=1024&height=1024&nologo=true"
        response = requests.get(url, timeout=30)
        if response.status_code == 200: return response.content
        return None
    try:
        image_bytes = await asyncio.to_thread(download_image)
        if image_bytes:
            image_file = discord.File(io.BytesIO(image_bytes), filename="cizim.jpg")
            await mesaj.delete()
            await ctx.send(content=f"🖼️ İşte resmin, {ctx.author.mention}!", file=image_file)
        else: await mesaj.edit(content="❌ Resim servisinden yanıt alınamadı.")
    except Exception as e: await mesaj.edit(content="❌ Teknik hata.")

@bot.command()
async def ask(ctx, *, soru: str = None):
    if soru is None:
        await ctx.send("❌ Sorunuzu yazın!")
        return
    mesaj = await ctx.send("🤔 *Düşünüyorum...*")
    def call_gemini():
        response = ai_client.models.generate_content(model='gemini-2.5-flash', contents=soru)
        return response.text
    try:
        cevap = await asyncio.to_thread(call_gemini)
        if len(cevap) > 2000:
            for i in range(0, len(cevap), 2000):
                if i == 0: await mesaj.edit(content=cevap[i:i+2000])
                else: await ctx.send(cevap[i:i+2000])
        else: await mesaj.edit(content=cevap)
    except Exception as e: await mesaj.edit(content="❌ Yanıt alınamadı.")

@bot.command()
async def weather(ctx, *, city: str = "İstanbul"):
    url = f"https://wttr.in/{city}?format=3&lang=tr"
    try:
        response = requests.get(url)
        if response.status_code == 200: await ctx.send(response.text)
        else: await ctx.send("Hava durumu alınamadı.")
    except: await ctx.send("Hata oluştu.")

@bot.command()
async def fact(ctx):
    response = requests.get("https://uselessfacts.jsph.pl/random.json")
    if response.status_code == 200: await ctx.send(response.json().get("text", "Veri yok."))

@bot.command()
async def translate(ctx, target_lang: str = None):
    if target_lang is None: return
    target_lang = target_lang.lower().strip()
    lang_name = LANGUAGES.get(target_lang, target_lang)
    duration = 5
    sample_rate = 44100
    await ctx.send(f"🎙️ **[{lang_name.upper()}]** için konuşun... (5 sn)")
    def record_audio():
        recording = sd.rec(int(duration * sample_rate), samplerate=sample_rate, channels=1, dtype="int16")
        sd.wait()
        wav.write("output.wav", sample_rate, recording)
    await asyncio.to_thread(record_audio)
    recognizer = sr.Recognizer()
    try:
        with sr.AudioFile("output.wav") as source: audio = recognizer.record(source)
        text = await asyncio.to_thread(recognizer.recognize_google, audio, language="tr")
    except:
        await ctx.send("❌ Ses çözülemedi.")
        return
    def translate_with_gemini():
        prompt = f"Metni sadece {lang_name} diline çevir: {text}"
        response = ai_client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
        return response.text.strip()
    try:
        translated_text = await asyncio.to_thread(translate_with_gemini)
        await ctx.send(f"🌍 **Çeviri:**\n> {translated_text}")
    except: await ctx.send("❌ Çeviri hatası.")

@bot.command()
async def quiz(ctx):
    all_langs = ", ".join([f"`{name}`" for code, name in LANGUAGES.items() if code != 'tr'])
    await ctx.send(f"🧠 Dil seçin:\n{all_langs}")
    def check_lang(m): return m.author == ctx.author and m.channel == ctx.channel
    try:
        lang_msg = await bot.wait_for('message', check=check_lang, timeout=30.0)
        selected_lang = LANGUAGES.get(lang_msg.content.lower().strip(), lang_msg.content.lower().strip())
        random_word = random.choice(TURKISH_WORDS)
        def get_quiz_answer():
            prompt = f"'{random_word}' kelimesinin {selected_lang} dilindeki karşılığı nedir? Sadece tek kelime yaz."
            response = ai_client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
            return response.text.lower().strip()
        correct_answer = await asyncio.to_thread(get_quiz_answer)
        await ctx.send(f"❓ **'{random_word.upper()}'** kelimesinin **{selected_lang}** karşılığı nedir?")
        answer_msg = await bot.wait_for('message', check=check_lang, timeout=20.0)
        if answer_msg.content.lower().strip() == correct_answer: await ctx.send("🎉 Doğru!")
        else: await ctx.send(f"❌ Yanlış! Cevap: `{correct_answer}`")
    except: await ctx.send("⏱️ Süre doldu veya hata oluştu.")


# 🚨 KOMUT YÖNETİCİSİ (on_message)
@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    # Komutların arka planda tetiklenmesini sağlar
    await bot.process_commands(message)

bot.run(TOKEN)