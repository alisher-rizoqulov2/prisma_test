import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from '../users/dto';
import * as bcrypt from 'bcrypt';
import { User } from '../../generated/prisma';
import { Response } from 'express';
import { access } from 'fs';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
  ) {}
  async generateTokens(user: User) {
    const payload = {
      id: user.id,
      is_active: user.is_active,
      email: user.email,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashed_refresh_token: refreshToken,
      },
    });
  }
  async signUp(createUserDto: CreateUserDto, res: Response) {
    const { email } = createUserDto;
    const condidate = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (condidate) {
      throw new ConflictException('Bunaqa emailli foydalanuvchi bor');
    }
    const { password, confirm_password, ...rest } = createUserDto;
    if (password !== confirm_password) {
      throw new BadRequestException('Parollar mos emas');
    }
    const hashed_password = await bcrypt.hash(password, 7);
    const user = await this.prismaService.user.create({
      data: { ...rest, hashed_password },
    });
    const tokens = await this.generateTokens(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refreshToken, 7);
    await this.updateRefreshToken(user.id, hashed_refresh_token);
    res.cookie('refreshToken', tokens.refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    return {
      message: 'New User signed Up',
      accessToken: tokens.accessToken,
    };
  }
}
