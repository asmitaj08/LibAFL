import struct

# Hexadecimal value 0x44 (decimal 68)
hex_value =30 

# Convert the integer value to binary data
binary_data = struct.pack('B', hex_value)

# Open the file in binary mode for writing
with open('binary_data.bin', 'wb') as f:
    # Write the binary data to the file
    f.write(binary_data)
