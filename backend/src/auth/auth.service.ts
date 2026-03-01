import {
    Injectable,
    ConflictException,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto, LoginDto } from './dto';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        private configService: ConfigService,
    ) { }

    // ============ REGISTER ============
    async register(dto: RegisterDto) {
        // Check if email or username already exists
        const existingUser = await this.prisma.user.findFirst({
            where: {
                OR: [{ email: dto.email }, { username: dto.username }],
            },
        });

        if (existingUser) {
            throw new ConflictException(
                existingUser.email === dto.email
                    ? 'Email already in use'
                    : 'Username already taken',
            );
        }

        // Hash the password
        const passwordHash = await bcrypt.hash(dto.password, 10);

        // Create a user
        const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                username: dto.username,
                passwordHash,
                firstName: dto.firstName,
                lastName: dto.lastName,
            },
        });

        // Generate tokens
        const tokens = await this.generateTokens(user.id, user.email, user.role);

        return {
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                role: user.role,
            },
            ...tokens,
        };
    }

    // ============ LOGIN ============
    async login(dto: LoginDto) {
        // Find user by email
        const user = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });

        if (!user || !user.passwordHash) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Compare password
        const passwordValid = await bcrypt.compare(dto.password, user.passwordHash);

        if (!passwordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Generate tokens
        const tokens = await this.generateTokens(user.id, user.email, user.role);

        return {
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                role: user.role,
            },
            ...tokens,
        };
    }

    // ============ REFRESH TOKEN ============
    async refreshTokens(userId: string) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        return this.generateTokens(user.id, user.email, user.role);
    }

    // ============ GET CURRENT USER ============
    async getMe(userId: string) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                username: true,
                firstName: true,
                lastName: true,
                bio: true,
                avatarUrl: true,
                role: true,
                createdAt: true,
            },
        });

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        return user;
    }

    // ============ HELPER: Generate Tokens ============
    private async generateTokens(userId: string, email: string, role: string) {
        // 1. Create the data to put INSIDE the token
        const payload = { sub: userId, email, role };

        // 2. Create both tokens at the same time
        const [accessToken, refreshToken] = await Promise.all([
            // Access token - signed with JWT_SECRET, expires in 15min
            this.jwtService.signAsync(payload, {
                secret: this.configService.get('JWT_SECRET'),
                expiresIn: this.configService.get('JWT_EXPIRES_IN'),
            }),
            // Refresh token - signed with different secret, expires in 7 days
            this.jwtService.signAsync(payload, {
                secret: this.configService.get('JWT_REFRESH_SECRET'),
                expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN'),
            }),
        ]);

        return { accessToken, refreshToken };
    }
}