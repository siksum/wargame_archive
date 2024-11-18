import asyncio
import discord
import os
import time
from discord.ext import commands

# Intents 설정
intents = discord.Intents.default()
intents.messages = True  # 메시지 이벤트를 수신하려면 활성화

game = discord.Game("Primary Bot")
bot = commands.Bot(command_prefix="!", intents=intents, status=discord.Status.online, activity=game, help_command=None)


@bot.event
async def on_ready():
    print(f'We have logged in as {bot.user}')  # 봇이 실행되면 콘솔창에 표시


@bot.command()
async def hello(ctx):
    await ctx.send(f'{ctx.author.mention}님 안녕하세요!')


@bot.command()
async def repeat(ctx, *, txt):
    await ctx.send(txt)


@bot.command()
async def hash(ctx):
    await ctx.send("해시에서 사용하고 있는 리눅스 쉘 이름은?")
    await asyncio.sleep(2)
    await ctx.send("ha'sh'")
    await asyncio.sleep(2)
    await ctx.send("ha ha 조크조크~")


@bot.command()
async def 메롱(ctx):
    await ctx.send("메\~~\~~롱~~")
    await asyncio.sleep(1)
    await ctx.send("눌렀대요~ 눌렀대요~")
    await asyncio.sleep(1)
    await ctx.send("아무것도 없는데 눌렀대요~~XD")
    await asyncio.sleep(1)
    await ctx.send("약오르지 까꿍><")
    await asyncio.sleep(1)
    await ctx.send("바아--보")


@bot.command()
async def summer(ctx):
    await ctx.send("HACK{C@n_y0u_man1pulat3_D1sc0rd_B0t?}")


@bot.command()
async def 여름아손(ctx):
    await ctx.send("으르르르르르ㅡ르응")
    await asyncio.sleep(2)
    await ctx.send("멍멍멍!!!!으르르르르르ㅡ르응멍멍멍!!!!왈왈왈왈오라왈왈오라!!!!!!!멍멍멍멍멍!!!!!!!!!오라왈왈와로알으르르르ㅡ르르으르르흐르으ㅡ르릉!!!!멍멍멍멍!!!!으르르르르르ㅡ르응멍멍멍!!!!왈왈왈왈오라왈왈오라!!!!!!!멍멍멍멍멍!!!!!!!!!오라왈왈와로알으르르르ㅡ르르으르르흐르으ㅡ르릉!!!!멍멍멍멍!!!!으르르르르르ㅡ르응멍멍멍!!!!왈왈왈왈오라왈왈오라!!!!!!!멍멍멍멍멍!!!!!!!!!오라왈왈와로알으르르르ㅡ르르으르르흐르으ㅡ르릉!!!!멍멍멍멍!!!!으르르르르르ㅡ르응멍멍멍!!!!왈왈왈왈오라왈왈오라!!!!!!!멍멍멍멍멍!!!!!!!!!오라왈왈와로알으르르르ㅡ르르으르")
    await asyncio.sleep(1)
    await ctx.send("Uppppps.. Sorry~")


@bot.command()
async def help(ctx):
    embed = discord.Embed(title="HashBot의 역할!", description="HashBot은요. 만능 박사에요!", color=0x4432a8)
    embed.add_field(name="!help", value="HashBot의 기능을 출력해줍니다.", inline=False)
    embed.add_field(name="!repeat", value="HashBot은 따라쟁이래요~", inline=False)
    embed.add_field(name="!hello", value="HashBot에게 인사를 받고 싶다면~~~!", inline=False)
    embed.add_field(name="!hash", value="이것을 누르면 행운이 찾아옵니다", inline=False)
    embed.add_field(name="!summer", value="flag를 얻고 싶나요?", inline=False)
    embed.add_field(name="!메롱", value="캬캬캬 눌러보라 나를!", inline=False)
    embed.add_field(name="!여름아손", value="우리 여름이는 정말 착해요!", inline=False)
    await ctx.send(embed=embed)


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("Error! 명령어를 찾지 못했습니다.")


bot.run('MTMwNjk5ODM0NTQyMzY1NDk0NQ.GLqbNi.dmd3cr2FRQhZxIjWZljSp5tO7N_VCUssmzrCKA') #토큰