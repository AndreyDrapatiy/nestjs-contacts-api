import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { ContactService } from '../services/contact.service';
import { JwtAuthGuard } from '../guards/auth/jwt.auth.guard';
import { Contact } from '../schemas/contact.schema';
import { RequestWithUser } from '../types';


@Controller('contacts')
export class ContactController {
  constructor(private readonly contactService: ContactService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  async getContacts(@Request() req: RequestWithUser): Promise<Contact[]> {
    return this.contactService.getContacts(req.user._id);
  }
}
