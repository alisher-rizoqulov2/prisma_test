import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("signUp")
  async signUp(
      @Body() createUsreDto:CreateUserDto,
      @Res({passthrough:true}) res:Response
    ){
      return this.authService.signUp(createUsreDto,res)
    }


}
