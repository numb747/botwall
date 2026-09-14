"""服务端生成的扭曲字符图 —— 一个已经被淘汰的范式，保留它是为了说清楚为什么。

为什么还要实现它
----------------
这种验证码在面向消费者的大流量站点已基本绝迹，但在政企与传统行业后台
（招投标、司法文书、工商、教务、银行后台）仍大量存在，而那正是相当一部分
采集业务的实际目标。所以它有真实价值，只是不在"主流站点"那条线上。

它为什么死了：生成器自带标注
----------------------------
这才是重点。服务端生成图片验证码有一个**结构性死穴**：生成它的程序同时知道
答案。于是任何人都能无限量地产出 (图像, 标签) 对——训练集是免费的。

这不是纸上推论，是可以跑的：

    python -m tools.captcha_dataset --count 5000 --out /tmp/ds

导出五千张带标签的样本，够训一个 CRNN 打到 95%+。**再怎么加难度也没用**，
因为攻击方的训练数据和你的生成器是同一个东西。而加难度会让人类失败率涨得
比机器快——这条线是不能往上抬的。

difficulty 三档正对应历史上的军备竞赛，也正好演示这条路走到了哪：

    lenient   干净字符 + 轻噪点        Tesseract 直接能读
    strict    逐字旋转 + 波形扭曲 + 干扰线
    paranoid  上述 + 字符重叠 + 彩色噪声背景

三档都挡不住自训模型。它们只是依次抬高**人类**的阅读成本。

可复现性的口径
--------------
**标签由 seed 密码学派生，跨机器跨版本一律稳定**——服务端据此无状态校验。
而像素级渲染依赖 Pillow 与字体版本，不保证逐字节一致。这个区分是有意的：
安全性只依赖标签，不依赖像素。
"""

from __future__ import annotations

import hashlib
import io
import math
import random
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageFilter, ImageFont

#: 剔除了形近字符：0/O、1/l/I、2/Z、5/S。
#: 真实实现都会这么做——它们提高机器识别难度的幅度，远小于提高人类误读率的幅度。
CHARSET = "34679ACDEFGHJKMNPQRTUVWXY"

WIDTH, HEIGHT = 200, 72


@dataclass(frozen=True)
class ImageChallenge:
    text: str
    png: bytes
    difficulty: str

    def matches(self, answer: str) -> bool:
        """大小写不敏感——真实实现都这样，否则人类失败率没法看。"""
        return answer.strip().upper() == self.text.upper()


def derive_text(seed: str, length: int = 5) -> str:
    """标签由 seed 派生，稳定且无需存储。

    用 sha256 而不是 random.Random：后者是 Python 的实现细节，跨版本不保证
    一致，而服务端要靠这个标签做无状态校验。
    """
    digest = hashlib.sha256(f"captcha::{seed}".encode()).digest()
    return "".join(CHARSET[b % len(CHARSET)] for b in digest[:length])


def generate(seed: str, difficulty: str = "strict", length: int = 5) -> ImageChallenge:
    text = derive_text(seed, length)
    png = _render(text, seed, difficulty)
    return ImageChallenge(text=text, png=png, difficulty=difficulty)


def _render(text: str, seed: str, difficulty: str) -> bytes:
    if difficulty not in ("lenient", "strict", "paranoid"):
        raise ValueError(f"未知难度: {difficulty}")

    # 视觉扰动用 random.Random 即可——像素不参与安全判定，只影响观感
    rng = random.Random(hashlib.sha256(f"render::{seed}".encode()).digest())

    image = Image.new("RGB", (WIDTH, HEIGHT), _background(rng, difficulty))
    draw = ImageDraw.Draw(image)

    if difficulty == "paranoid":
        _draw_texture(draw, rng)

    _draw_text(image, text, rng, difficulty)

    if difficulty != "lenient":
        _draw_interference(draw, rng, difficulty)

    _draw_noise(draw, rng, difficulty)

    if difficulty != "lenient":
        image = _wave(image, rng)
        image = image.filter(ImageFilter.SMOOTH)

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _background(rng: random.Random, difficulty: str) -> tuple[int, int, int]:
    if difficulty == "paranoid":
        return tuple(rng.randint(200, 245) for _ in range(3))  # type: ignore[return-value]
    return (255, 255, 255)


def _ink(rng: random.Random, difficulty: str) -> tuple[int, int, int]:
    if difficulty == "lenient":
        return (20, 20, 20)
    return tuple(rng.randint(0, 110) for _ in range(3))  # type: ignore[return-value]


def _font(size: int) -> ImageFont.FreeTypeFont:
    """用 Pillow 自带字体，不碰系统字体。

    依赖系统字体会让同一份 profile 在不同机器上渲染出不同的图——靶场的
    可复现承诺不该栽在"这台机器装没装某个字体"上。
    """
    return ImageFont.load_default(size=size)


def _draw_text(image: Image.Image, text: str, rng: random.Random, difficulty: str) -> None:
    """逐字绘制。每个字单独成图再旋转，才能做出字符级的角度差异。"""
    overlap = {"lenient": 0, "strict": 2, "paranoid": 7}[difficulty]
    max_angle = {"lenient": 0, "strict": 22, "paranoid": 34}[difficulty]

    slot = (WIDTH - 20) // len(text)
    x = 12
    for char in text:
        size = rng.randint(34, 44) if difficulty != "lenient" else 40
        font = _font(size)
        tile = Image.new("RGBA", (size + 20, size + 20), (0, 0, 0, 0))
        ImageDraw.Draw(tile).text((10, 4), char, font=font, fill=(*_ink(rng, difficulty), 255))
        if max_angle:
            tile = tile.rotate(rng.uniform(-max_angle, max_angle), resample=Image.BICUBIC, expand=1)
        y = rng.randint(0, max(1, HEIGHT - tile.height)) if difficulty != "lenient" else 10
        image.paste(tile, (x, y), tile)
        x += slot - overlap


def _draw_interference(draw: ImageDraw.ImageDraw, rng: random.Random, difficulty: str) -> None:
    """干扰线。

    注意它们画在字符**之后**——画在下层的干扰几乎不影响识别，因为连通域
    仍然可分。这正是很多实现无效的原因，这里刻意做对，让难度是真的。
    """
    count = 3 if difficulty == "strict" else 6
    for _ in range(count):
        color = tuple(rng.randint(60, 170) for _ in range(3))
        points = [(rng.randint(0, WIDTH), rng.randint(0, HEIGHT)) for _ in range(3)]
        draw.line(points, fill=color, width=rng.randint(1, 2))


def _draw_noise(draw: ImageDraw.ImageDraw, rng: random.Random, difficulty: str) -> None:
    count = {"lenient": 120, "strict": 500, "paranoid": 1100}[difficulty]
    for _ in range(count):
        xy = (rng.randint(0, WIDTH - 1), rng.randint(0, HEIGHT - 1))
        draw.point(xy, fill=tuple(rng.randint(0, 200) for _ in range(3)))


def _draw_texture(draw: ImageDraw.ImageDraw, rng: random.Random) -> None:
    for _ in range(14):
        x0, y0 = rng.randint(-20, WIDTH), rng.randint(-20, HEIGHT)
        draw.ellipse(
            [x0, y0, x0 + rng.randint(20, 60), y0 + rng.randint(20, 60)],
            outline=tuple(rng.randint(180, 225) for _ in range(3)),
        )


def _wave(image: Image.Image, rng: random.Random) -> Image.Image:
    """正弦波扭曲。破坏字符的直线基线，让按列切分的朴素分割失效。"""
    amplitude = rng.uniform(2.5, 5.0)
    period = rng.uniform(28.0, 55.0)
    phase = rng.uniform(0, math.tau)
    source = image.copy()
    output = Image.new("RGB", image.size, (255, 255, 255))
    for x in range(image.width):
        offset = int(amplitude * math.sin(phase + x / period * math.tau))
        column = source.crop((x, 0, x + 1, image.height))
        output.paste(column, (x, offset))
    return output
