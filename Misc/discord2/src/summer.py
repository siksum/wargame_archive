import asyncio, discord, os, time, random
from discord.ext import commands

# Intents 설정
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True  # 메시지 내용 접근을 활성화

game = discord.Game("Dice Gaming...")
bot = commands.Bot(command_prefix="!", intents=intents, status=discord.Status.online, activity=game, help_command=None)


@bot.event
async def on_ready():
    print(f'We have logged in as {bot.user}')  # 봇이 실행되면 콘솔창에 표시


# 주사위 기능
def dicedefine(i):
    dice0 = {1: '⚀=1', 2: '⚁=2', 3: '⚂=3', 4: '⚃=4', 5: '⚄=5', 6: '⚅=6'}  # 딕셔너리
    dice = random.randint(1, 7)
    dice1 = dice0[dice]
    return dice1 if i == 1 else (dice, dice1)


@bot.command()
async def dice(ctx, text):
    if text is None:  # 추가 입력이 없으면 하나만 굴림
        embed = discord.Embed(title="주사위 굴리는 중..", color=0x4432a8)
        dice1 = dicedefine(1)
        embed.add_field(name=":game_die:", value=f"{dice1}", inline=True)
        await ctx.send(embed=embed)
    else:  # 추가 입력이 있음
        if text.isdigit():  # 입력이 숫자인지 확인
            if int(text) < 11:
                embed = discord.Embed(title="주사위 굴리는 중..", color=0x4432a8)
                _sum = 0  # 주사위 합
                text = int(text)
                for i in range(text):
                    buf, dice1 = dicedefine(2)
                    _sum += buf
                    embed.add_field(name=f"{i+1}:game_die:", value=f"{dice1}", inline=True)
                embed.set_footer(text=f"주사위의 합 = {_sum}")
                if _sum > 40:
                    embed.add_field(name="You Got It!", value="HACK{D1sc0rd_B0t_Als0", inline=False)
                await ctx.send(embed=embed)
            else:
                await ctx.send("너무 커요!!")
        else:
            await ctx.send("숫자만 가능합니다.")


def dice():
    a = random.randint(4, 7)
    b = random.randint(1, 7)
    if a > b:
        return "패배", 0xFF0000, str(a), str(b)
    elif a == b:
        return "무승부", 0xFAFA00, str(a), str(b)
    else:
        return "승리", 0x00ff56, str(a), str(b)


@bot.command()
async def dice2(ctx):
    result, _color, bot, user = dice()
    embed = discord.Embed(title="주사위 게임 결과", description="무시무시한 여름이를 물리치기 위해서는 여름이를 이겨야 해요!!", color=_color)
    embed.add_field(name="여름이의 숫자", value=f":game_die: {bot}", inline=True)
    embed.add_field(name=f"{ctx.author.name}의 숫자", value=f":game_die: {user}", inline=True)
    embed.set_footer(text=f"결과: {result}")
    if result == "승리":
        embed.add_field(name="여름이를 이긴 당신.. 강하다..", value="_C@n_P1aY_D1c3_G@M3!}", inline=False)
    await ctx.send(embed=embed)

@bot.command()
async def 여름아노래불러줘(ctx, text):
     embed = discord.Embed(title="여름이의 노래방!", description="여름이의 감미로운 노래.. 감당하실 수 있으십니까?", color=0x4432a8)
     if text == '만만하니':
        embed.add_field(name="여름이가 부릅니다. 유키스의 만만하니..", value="너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄 너완전zzㅏ증나 ! 여우🦊같은girl~🤘👄", inline=False)
     elif text == '롤린':
         embed.add_field(name="여름이가 부릅니다. 브레이브걸스의 롤린..", value="<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣<😆> 롤린롤린롤린🌀 <😆> 롤린롤린롤린🌀 하루👆가 멀다하고💋 롤린🌀인더딥🤣", inline=False)
     elif text == '돌핀':
         embed.add_field(name="여름이가 부릅니다. 오마이걸의 돌핀..", value="🌊🌊또🌊물보라를🌊일으켜🌊다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다.🌊🌊또🌊물보라를🌊일으켜🌊다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다..🐬..다...🐬...다다다..🐬...다다다...🌊🌊또🌊물보라를🌊일으켜🌊🌊 ..다..🐬..다..🐬..다.", inline=False)
     else:
         embed.add_field(name="Oh Sorry.. 여름이는 아직 그거까진 못해요..", value = "좀 더 연습해서 들려드릴게요XD")
     await ctx.send(embed=embed)

@bot.command()
async def 화이팅(ctx):
    await ctx.send(f'{ctx.author.mention}님, 오늘 하루도 고생많았어요!')
    time.sleep(1)
    await ctx.send(f"항상 {ctx.author.mention}님을 응원하고 있답니다!")
    time.sleep(1)
    await ctx.send("함께 해줘서 고마워요.")
    time.sleep(1)
    await ctx.send("하는 일 모두 잘되길 응원할게요:) 화이팅!")


@bot.command()
async def help(ctx):
    embed = discord.Embed(title="여름이의 역할!", description="여름이는 주사위 던지는 것을 좋아해요!", color=0x4432a8)
    embed.add_field(name="!help", value="여름이봇의 기능을 출력해줍니다.", inline=False)
    embed.add_field(name="!dice", value="주사위를 던지다보면 flag가 나올지도..!", inline=False)
    embed.add_field(name="!dice2", value="여름이를 이기면 flag가 나올지도..!", inline=False)
    embed.add_field(name="!여름아노래불러줘", value="여름이는 만만하니, 롤린, 돌핀을 부를 수 있어요!", inline=False)
    embed.add_field(name="!화이팅", value=f"{ctx.author.mention}님께 전하는말!")
    await ctx.send(embed=embed)


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("Error! 명령어를 찾지 못했습니다.")


# 봇 실행 (토큰 추가)
bot.run('OTA5MjkyMDAyNTQ0MzQxMDQy.GATxTm.McK8_cpOWdspBVsoZvWNkUT21bgdZOA9YjdvDQ')  # 실제 봇 토큰으로 변경
