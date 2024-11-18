import asyncio, discord, os, time, random
from discord.ext import commands

# Intents 설정
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True  # 메시지 내용 접근을 활성화

game = discord.Game("비밀을 갖고 입 꾹닫기")
bot = commands.Bot(command_prefix="!", intents=intents, status=discord.Status.online, activity=game, help_command=None)


@bot.event
async def on_ready():
    print(f'We have logged in as {bot.user}')  # 봇이 실행되면 콘솔창에 표시
    

@bot.command()
async def 여름아답을알려줘(ctx):
    await ctx.send(f'{ctx.author.mention}씨!!!')
    time.sleep(1)
    
    if len(ctx.author.roles) == 1 or len(ctx.author.roles) == 0:
        await ctx.send(f"우엥 이상한 사람..")
        await ctx.send(f"저랑 얘기하고 싶으면 `여름이 친구` 정도는 되어야해요! 메롱")
        await ctx.send("🌈무지개반사🌌우주반사🏅절대반사🌚블랙홀반사🙌🏻자동반사💎크리스탈반사👑슈퍼울트라반사🐉흑염룡반사💫안드로메다반사☃️알래스카반사🐺시베리아허스키반사🌞복사열반사👻유령반사👾외계인반사🤖인공지능반사⚜️제우스반사🎵리듬에몸을맡기고반사👁호루스의눈반사🖕법규반사🕴무중력반사🌪허리케인반사")
        
    if ctx.author.roles[1].name == 'human':
        await ctx.send(f"우리 언니가 `{ctx.author.roles[1].name}`인 사람이랑 말하지 말라고 그랬어요")
        await ctx.send(f"저랑 얘기하고 싶으면 `여름이 친구` 정도는 되어야해요! 메롱")
        await ctx.send("🌈무지개반사🌌우주반사🏅절대반사🌚블랙홀반사🙌🏻자동반사💎크리스탈반사👑슈퍼울트라반사🐉흑염룡반사💫안드로메다반사☃️알래스카반사🐺시베리아허스키반사🌞복사열반사👻유령반사👾외계인반사🤖인공지능반사⚜️제우스반사🎵리듬에몸을맡기고반사👁호루스의눈반사🖕법규반사🕴무중력반사🌪허리케인반사")
    
    elif ctx.author.roles[1].name == '여름이 친구':
        await ctx.send(f"{ctx.author.mention}는 내 친구 맞아요!!")
        await ctx.send(f"언니가 아무한테 말해주지 말라그랬는데 {ctx.author.mention}는 내 친구니까 말해줄게요!")
        await ctx.send(f"HACK{{D0_y0u_h4v3_perm1ss0n?}}")
        
    time.sleep(1)


@bot.command()
async def hello(ctx):
    await ctx.send(f'{ctx.author.mention}! 우리 언니 친구인가요? 반가워요!')

@bot.command()
async def help(ctx):
    embed = discord.Embed(title="여름이의 역할!", description="여름이는 주사위 던지는 것을 좋아해요!", color=0x4432a8)
    embed.add_field(name="!help", value="여름이봇의 기능을 출력해줍니다.", inline=False)
    embed.add_field(name="!hello", value="여름이가 반겨줍니다.", inline=False)
    embed.add_field(name="!여름아답을알려줘", value="여름이의 친구가 된다면 flag가 나올지도..!", inline=False)
    await ctx.send(embed=embed)


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("여름이는 그런 말 몰라용")


# 봇 실행 (토큰 추가)
bot.run('OTEwNDM5MzExNTg4MDY5NDM2.GLgAd3.PKvCONR4XL7yBjNBiH97OURQWV2pV4l9CqDIqw')  # 실제 봇 토큰으로 변경
