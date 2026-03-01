import { Controller, Post, Body, Get, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from './dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { GetUser } from './decorators/get-user.decorator';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('register')
    register(@Body() dto: RegisterDto) {
        return this.authService.register(dto);
    }

    @Post('login')
    login(@Body() dto: LoginDto) {
        return this.authService.login(dto);
    }

    @UseGuards(JwtRefreshGuard)
    @Post('refresh')
    refreshTokens(@GetUser('id') userId: string) {
        return this.authService.refreshTokens(userId);
    }

    @UseGuards(JwtAuthGuard)
    @Get('me')
    getMe(@GetUser('id') userId: string) {
        return this.authService.getMe(userId);
    }
}