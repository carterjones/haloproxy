/*

Show_dump 0.1.1a

    Copyright 2004,2005,2006 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt

This function, optimized for performace, shows the hex dump of a buffer and
places it in a stream

Usage:
        show_dump(buffer, buffer_length, stdout);
        show_dump(buffer, buffer_length, fd);
*/

#include <string.h>

typedef enum { false, true } bool;

void show_dump(unsigned char *data, unsigned int len, FILE *stream, bool is_client) {
    const static char       hex[] = "0123456789abcdef";
    static unsigned char    buff[67];   /* HEX  CHAR\n */
    unsigned char           chr,
                            *bytes,
                            *p,
                            *limit,
                            *glimit = data + len;
    unsigned int            num_bytes_added = 0;

    if (is_client == false)
    {
        return;
    }

    memset(buff + 2, ' ', 48);

    // While the address of the current byte of data being printed is
    // less than the total length of the data...
    while(data < glimit) {

        // limit = 16 bytes after the current byte being printed
        limit = data + 16;

        // if the limit is greater than the last byte of data to be printed...
        if(limit > glimit) {
            // set the limit to the last byte of data to be printed
            limit = glimit;

            // set buff to 48 bytes of <space>
            memset(buff, ' ', 48);
        }

        // p = the address of the receiving buffer that holds the data to be printed
        p     = buff;

        // bytes = 50 bytes after the address of the receiving buffer that
        // holds the data to be printed. the purpose of this is to have bytes
        // in their own column on the right.
        bytes = p + 50;

        // while the current byte being printed is less than the limit...
        while(data < limit) {
            // the current character equals the value at the current address of data
            chr = *data;

            // p = the left hex character of the current byte (increment p)
            *p++ = hex[chr >> 4];

            // p = the right hex character of the current byte (increment p)
            *p++ = hex[chr & 15];

            // increment p
            p++;

            // the current byte: either the character or a period
            //*bytes++ = ((chr < ' ') || (chr >= 0x7f)) ? '.' : chr;

            // move to the next byte being printed
            data++;
            num_bytes_added++;
        }

        // add a newline character
        //*bytes++ = '\n';

        unsigned int num_characters_to_print = num_bytes_added * 3;
        num_bytes_added = 0;

        // print the current portion of the buffer that has just been
        // populated with hex representations and bits
        fwrite(buff, num_characters_to_print, 1, stream);
    }
}

