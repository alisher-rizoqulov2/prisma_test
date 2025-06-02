import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto';
import { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signUp')
  async signUp(
    @Body() createUsreDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.signUp(createUsreDto, res);
  }
  @Post('signIn')
  async signIp(
    @Body() LoginUsreDto: loginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.signIn(LoginUsreDto, res);
  }
  @Post('refresh-tokens')
  async refreshTokens(@Req() req: Request, @Res() res: Response) {
    const result = await this.authService.refreshTokens(req, res);
    return res.json(result);
  }

  @Post('signout')
  async signOut(@Req() req: Request, @Res() res: Response) {
    const result = await this.authService.signOut(req, res);
    return res.json(result);
  }
}
