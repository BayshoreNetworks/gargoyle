'''
 
  GARGOYLE_PSCAND: Gargoyle Port Scan Detector
  
  Wrapper for admin functions
 
  Copyright (c) 2017, Bayshore Networks, Inc.
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without modification, are permitted provided that
  the following conditions are met:
  
  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
  following disclaimer.
  
  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
  following disclaimer in the documentation and/or other materials provided with the distribution.
  
  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
  products derived from this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Code within starred lines:
  Project: ipaddr-py https://github.com/google/ipaddr-py/blob/master/ipaddr.py
  Copyright (c) 2007, Google Inc.
  License (Apache) http://www.apache.org/licenses/LICENSE-2.0

'''
from subprocess import *
import sqlite3
import json
import os
import time
import struct
import re
from datetime import datetime
import subprocess
import syslog

''' *********************************************************************************************************** '''
IPV4LENGTH = 32
IPV6LENGTH = 128

class AddressValueError(ValueError):
    """A Value Error related to the address."""


class NetmaskValueError(ValueError):
    """A Value Error related to the netmask."""

class _IPAddrBase(object):

    """The mother class."""

    def __index__(self):
        return self._ip

    def __int__(self):
        return self._ip

    def __hex__(self):
        return hex(self._ip)

    @property
    def exploded(self):
        """Return the longhand version of the IP address as a string."""
        return self._explode_shorthand_ip_string()

    @property
    def compressed(self):
        """Return the shorthand version of the IP address as a string."""
        return str(self)


class _BaseIP(_IPAddrBase):

    """A generic IP object.

    This IP class contains the version independent methods which are
    used by single IP addresses.

    """

    def __eq__(self, other):
        try:
            return (self._ip == other._ip
                    and self._version == other._version)
        except AttributeError:
            return NotImplemented

    def __ne__(self, other):
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __le__(self, other):
        gt = self.__gt__(other)
        if gt is NotImplemented:
            return NotImplemented
        return not gt

    def __ge__(self, other):
        lt = self.__lt__(other)
        if lt is NotImplemented:
            return NotImplemented
        return not lt

    def __lt__(self, other):
        if self._version != other._version:
            raise TypeError('%s and %s are not of the same version' % (
                    str(self), str(other)))
        if not isinstance(other, _BaseIP):
            raise TypeError('%s and %s are not of the same type' % (
                    str(self), str(other)))
        if self._ip != other._ip:
            return self._ip < other._ip
        return False

    def __gt__(self, other):
        if self._version != other._version:
            raise TypeError('%s and %s are not of the same version' % (
                    str(self), str(other)))
        if not isinstance(other, _BaseIP):
            raise TypeError('%s and %s are not of the same type' % (
                    str(self), str(other)))
        if self._ip != other._ip:
            return self._ip > other._ip
        return False

    # Shorthand for Integer addition and subtraction. This is not
    # meant to ever support addition/subtraction of addresses.
    def __add__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        return IPAddress(int(self) + other, version=self._version)

    def __sub__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        return IPAddress(int(self) - other, version=self._version)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

    def __str__(self):
        return  '%s' % self._string_from_ip_int(self._ip)

    def __hash__(self):
        return hash(hex(long(self._ip)))

    def _get_address_key(self):
        return (self._version, self)

    @property
    def version(self):
        raise NotImplementedError('BaseIP has no version')


class _BaseNet(_IPAddrBase):

    """A generic IP object.

    This IP class contains the version independent methods which are
    used by networks.

    """

    def __init__(self, address):
        self._cache = {}

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

    def iterhosts(self):
        """Generate Iterator over usable hosts in a network.

           This is like __iter__ except it doesn't return the network
           or broadcast addresses.

        """
        cur = int(self.network) + 1
        bcast = int(self.broadcast) - 1
        while cur <= bcast:
            cur += 1
            yield IPAddress(cur - 1, version=self._version)

    def __iter__(self):
        cur = int(self.network)
        bcast = int(self.broadcast)
        while cur <= bcast:
            cur += 1
            yield IPAddress(cur - 1, version=self._version)

    def __getitem__(self, n):
        network = int(self.network)
        broadcast = int(self.broadcast)
        if n >= 0:
            if network + n > broadcast:
                raise IndexError
            return IPAddress(network + n, version=self._version)
        else:
            n += 1
            if broadcast + n < network:
                raise IndexError
            return IPAddress(broadcast + n, version=self._version)

    def __lt__(self, other):
        if self._version != other._version:
            raise TypeError('%s and %s are not of the same version' % (
                    str(self), str(other)))
        if not isinstance(other, _BaseNet):
            raise TypeError('%s and %s are not of the same type' % (
                    str(self), str(other)))
        if self.network != other.network:
            return self.network < other.network
        if self.netmask != other.netmask:
            return self.netmask < other.netmask
        return False

    def __gt__(self, other):
        if self._version != other._version:
            raise TypeError('%s and %s are not of the same version' % (
                    str(self), str(other)))
        if not isinstance(other, _BaseNet):
            raise TypeError('%s and %s are not of the same type' % (
                    str(self), str(other)))
        if self.network != other.network:
            return self.network > other.network
        if self.netmask != other.netmask:
            return self.netmask > other.netmask
        return False

    def __le__(self, other):
        gt = self.__gt__(other)
        if gt is NotImplemented:
            return NotImplemented
        return not gt

    def __ge__(self, other):
        lt = self.__lt__(other)
        if lt is NotImplemented:
            return NotImplemented
        return not lt

    def __eq__(self, other):
        try:
            return (self._version == other._version
                    and self.network == other.network
                    and int(self.netmask) == int(other.netmask))
        except AttributeError:
            if isinstance(other, _BaseIP):
                return (self._version == other._version
                        and self._ip == other._ip)

    def __ne__(self, other):
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __str__(self):
        return  '%s/%s' % (str(self.ip),
                           str(self._prefixlen))

    def __hash__(self):
        return hash(int(self.network) ^ int(self.netmask))

    def __contains__(self, other):
        # always false if one is v4 and the other is v6.
        if self._version != other._version:
          return False
        # dealing with another network.
        if isinstance(other, _BaseNet):
            return (self.network <= other.network and
                    self.broadcast >= other.broadcast)
        # dealing with another address
        else:
            return (int(self.network) <= int(other._ip) <=
                    int(self.broadcast))

    def overlaps(self, other):
        """Tell if self is partly contained in other."""
        return self.network in other or self.broadcast in other or (
            other.network in self or other.broadcast in self)

    @property
    def network(self):
        x = self._cache.get('network')
        if x is None:
            x = IPAddress(self._ip & int(self.netmask), version=self._version)
            self._cache['network'] = x
        return x

    @property
    def broadcast(self):
        x = self._cache.get('broadcast')
        if x is None:
            x = IPAddress(self._ip | int(self.hostmask), version=self._version)
            self._cache['broadcast'] = x
        return x

    @property
    def hostmask(self):
        x = self._cache.get('hostmask')
        if x is None:
            x = IPAddress(int(self.netmask) ^ self._ALL_ONES,
                          version=self._version)
            self._cache['hostmask'] = x
        return x

    @property
    def with_prefixlen(self):
        return '%s/%d' % (str(self.ip), self._prefixlen)

    @property
    def with_netmask(self):
        return '%s/%s' % (str(self.ip), str(self.netmask))

    @property
    def with_hostmask(self):
        return '%s/%s' % (str(self.ip), str(self.hostmask))

    @property
    def numhosts(self):
        """Number of hosts in the current subnet."""
        return int(self.broadcast) - int(self.network) + 1

    @property
    def version(self):
        raise NotImplementedError('BaseNet has no version')

    @property
    def prefixlen(self):
        return self._prefixlen

    def address_exclude(self, other):
        """Remove an address from a larger block.

        For example:

            addr1 = IPNetwork('10.1.1.0/24')
            addr2 = IPNetwork('10.1.1.0/26')
            addr1.address_exclude(addr2) =
                [IPNetwork('10.1.1.64/26'), IPNetwork('10.1.1.128/25')]

        or IPv6:

            addr1 = IPNetwork('::1/32')
            addr2 = IPNetwork('::1/128')
            addr1.address_exclude(addr2) = [IPNetwork('::0/128'),
                IPNetwork('::2/127'),
                IPNetwork('::4/126'),
                IPNetwork('::8/125'),
                ...
                IPNetwork('0:0:8000::/33')]

        Args:
            other: An IPvXNetwork object of the same type.

        Returns:
            A sorted list of IPvXNetwork objects addresses which is self
            minus other.

        Raises:
            TypeError: If self and other are of difffering address
              versions, or if other is not a network object.
            ValueError: If other is not completely contained by self.

        """
        if not self._version == other._version:
            raise TypeError("%s and %s are not of the same version" % (
                str(self), str(other)))

        if not isinstance(other, _BaseNet):
            raise TypeError("%s is not a network object" % str(other))

        if other not in self:
            raise ValueError('%s not contained in %s' % (str(other),
                                                         str(self)))
        if other == self:
            return []

        ret_addrs = []

        # Make sure we're comparing the network of other.
        other = IPNetwork('%s/%s' % (str(other.network), str(other.prefixlen)),
                   version=other._version)

        s1, s2 = self.subnet()
        while s1 != other and s2 != other:
            if other in s1:
                ret_addrs.append(s2)
                s1, s2 = s1.subnet()
            elif other in s2:
                ret_addrs.append(s1)
                s1, s2 = s2.subnet()
            else:
                # If we got here, there's a bug somewhere.
                assert True == False, ('Error performing exclusion: '
                                       's1: %s s2: %s other: %s' %
                                       (str(s1), str(s2), str(other)))
        if s1 == other:
            ret_addrs.append(s2)
        elif s2 == other:
            ret_addrs.append(s1)
        else:
            # If we got here, there's a bug somewhere.
            assert True == False, ('Error performing exclusion: '
                                   's1: %s s2: %s other: %s' %
                                   (str(s1), str(s2), str(other)))

        return sorted(ret_addrs, key=_BaseNet._get_networks_key)

    def compare_networks(self, other):
        """Compare two IP objects.

        This is only concerned about the comparison of the integer
        representation of the network addresses.  This means that the
        host bits aren't considered at all in this method.  If you want
        to compare host bits, you can easily enough do a
        'HostA._ip < HostB._ip'

        Args:
            other: An IP object.

        Returns:
            If the IP versions of self and other are the same, returns:

            -1 if self < other:
              eg: IPv4('1.1.1.0/24') < IPv4('1.1.2.0/24')
              IPv6('1080::200C:417A') < IPv6('1080::200B:417B')
            0 if self == other
              eg: IPv4('1.1.1.1/24') == IPv4('1.1.1.2/24')
              IPv6('1080::200C:417A/96') == IPv6('1080::200C:417B/96')
            1 if self > other
              eg: IPv4('1.1.1.0/24') > IPv4('1.1.0.0/24')
              IPv6('1080::1:200C:417A/112') >
              IPv6('1080::0:200C:417A/112')

            If the IP versions of self and other are different, returns:

            -1 if self._version < other._version
              eg: IPv4('10.0.0.1/24') < IPv6('::1/128')
            1 if self._version > other._version
              eg: IPv6('::1/128') > IPv4('255.255.255.0/24')

        """
        if self._version < other._version:
            return -1
        if self._version > other._version:
            return 1
        # self._version == other._version below here:
        if self.network < other.network:
            return -1
        if self.network > other.network:
            return 1
        # self.network == other.network below here:
        if self.netmask < other.netmask:
            return -1
        if self.netmask > other.netmask:
            return 1
        # self.network == other.network and self.netmask == other.netmask
        return 0

    def _get_networks_key(self):
        """Network-only key function.

        Returns an object that identifies this address' network and
        netmask. This function is a suitable "key" argument for sorted()
        and list.sort().

        """
        return (self._version, self.network, self.netmask)

    def _ip_int_from_prefix(self, prefixlen):
        """Turn the prefix length into a bitwise netmask.

        Args:
            prefixlen: An integer, the prefix length.

        Returns:
            An integer.

        """
        return self._ALL_ONES ^ (self._ALL_ONES >> prefixlen)

    def _prefix_from_ip_int(self, ip_int):
        """Return prefix length from a bitwise netmask.

        Args:
            ip_int: An integer, the netmask in expanded bitwise format.

        Returns:
            An integer, the prefix length.

        Raises:
            NetmaskValueError: If the input is not a valid netmask.

        """
        prefixlen = self._max_prefixlen
        while prefixlen:
            if ip_int & 1:
                break
            ip_int >>= 1
            prefixlen -= 1

        if ip_int == (1 << prefixlen) - 1:
            return prefixlen
        else:
            raise NetmaskValueError('Bit pattern does not match /1*0*/')

    def _prefix_from_prefix_int(self, prefixlen):
        """Validate and return a prefix length integer.

        Args:
            prefixlen: An integer containing the prefix length.

        Returns:
            The input, possibly converted from long to int.

        Raises:
            NetmaskValueError: If the input is not an integer, or out of range.
        """
        if not isinstance(prefixlen, (int, long)):
            raise NetmaskValueError('%r is not an integer' % prefixlen)
        prefixlen = int(prefixlen)
        if not (0 <= prefixlen <= self._max_prefixlen):
            raise NetmaskValueError('%d is not a valid prefix length' %
                                    prefixlen)
        return prefixlen

    def _prefix_from_prefix_string(self, prefixlen_str):
        """Turn a prefix length string into an integer.

        Args:
            prefixlen_str: A decimal string containing the prefix length.

        Returns:
            The prefix length as an integer.

        Raises:
            NetmaskValueError: If the input is malformed or out of range.

        """
        try:
            if not _BaseV4._DECIMAL_DIGITS.issuperset(prefixlen_str):
                raise ValueError
            prefixlen = int(prefixlen_str)
        except ValueError:
            raise NetmaskValueError('%s is not a valid prefix length' %
                                    prefixlen_str)
        return self._prefix_from_prefix_int(prefixlen)

    def _prefix_from_ip_string(self, ip_str):
        """Turn a netmask/hostmask string into a prefix length.

        Args:
            ip_str: A netmask or hostmask, formatted as an IP address.

        Returns:
            The prefix length as an integer.

        Raises:
            NetmaskValueError: If the input is not a netmask or hostmask.

        """
        # Parse the netmask/hostmask like an IP address.
        try:
            ip_int = self._ip_int_from_string(ip_str)
        except AddressValueError:
            raise NetmaskValueError('%s is not a valid netmask' % ip_str)

        # Try matching a netmask (this would be /1*0*/ as a bitwise regexp).
        # Note that the two ambiguous cases (all-ones and all-zeroes) are
        # treated as netmasks.
        try:
            return self._prefix_from_ip_int(ip_int)
        except NetmaskValueError:
            pass

        # Invert the bits, and try matching a /0+1+/ hostmask instead.
        ip_int ^= self._ALL_ONES
        try:
            return self._prefix_from_ip_int(ip_int)
        except NetmaskValueError:
            raise NetmaskValueError('%s is not a valid netmask' % ip_str)

    def iter_subnets(self, prefixlen_diff=1, new_prefix=None):
        """The subnets which join to make the current subnet.

        In the case that self contains only one IP
        (self._prefixlen == 32 for IPv4 or self._prefixlen == 128
        for IPv6), return a list with just ourself.

        Args:
            prefixlen_diff: An integer, the amount the prefix length
              should be increased by. This should not be set if
              new_prefix is also set.
            new_prefix: The desired new prefix length. This must be a
              larger number (smaller prefix) than the existing prefix.
              This should not be set if prefixlen_diff is also set.

        Returns:
            An iterator of IPv(4|6) objects.

        Raises:
            ValueError: The prefixlen_diff is too small or too large.
                OR
            prefixlen_diff and new_prefix are both set or new_prefix
              is a smaller number than the current prefix (smaller
              number means a larger network)

        """
        if self._prefixlen == self._max_prefixlen:
            yield self
            return

        if new_prefix is not None:
            if new_prefix < self._prefixlen:
                raise ValueError('new prefix must be longer')
            if prefixlen_diff != 1:
                raise ValueError('cannot set prefixlen_diff and new_prefix')
            prefixlen_diff = new_prefix - self._prefixlen

        if prefixlen_diff < 0:
            raise ValueError('prefix length diff must be > 0')
        new_prefixlen = self._prefixlen + prefixlen_diff

        if new_prefixlen > self._max_prefixlen:
            raise ValueError(
                'prefix length diff %d is invalid for netblock %s' % (
                    new_prefixlen, str(self)))

        first = IPNetwork('%s/%s' % (str(self.network),
                                     str(self._prefixlen + prefixlen_diff)),
                         version=self._version)

        yield first
        current = first
        while True:
            broadcast = current.broadcast
            if broadcast == self.broadcast:
                return
            new_addr = IPAddress(int(broadcast) + 1, version=self._version)
            current = IPNetwork('%s/%s' % (str(new_addr), str(new_prefixlen)),
                                version=self._version)

            yield current

    def masked(self):
        """Return the network object with the host bits masked out."""
        return IPNetwork('%s/%d' % (self.network, self._prefixlen),
                         version=self._version)

    def subnet(self, prefixlen_diff=1, new_prefix=None):
        """Return a list of subnets, rather than an iterator."""
        return list(self.iter_subnets(prefixlen_diff, new_prefix))

    def supernet(self, prefixlen_diff=1, new_prefix=None):
        """The supernet containing the current network.

        Args:
            prefixlen_diff: An integer, the amount the prefix length of
              the network should be decreased by.  For example, given a
              /24 network and a prefixlen_diff of 3, a supernet with a
              /21 netmask is returned.

        Returns:
            An IPv4 network object.

        Raises:
            ValueError: If self.prefixlen - prefixlen_diff < 0. I.e., you have a
              negative prefix length.
                OR
            If prefixlen_diff and new_prefix are both set or new_prefix is a
              larger number than the current prefix (larger number means a
              smaller network)

        """
        if self._prefixlen == 0:
            return self

        if new_prefix is not None:
            if new_prefix > self._prefixlen:
                raise ValueError('new prefix must be shorter')
            if prefixlen_diff != 1:
                raise ValueError('cannot set prefixlen_diff and new_prefix')
            prefixlen_diff = self._prefixlen - new_prefix


        if self.prefixlen - prefixlen_diff < 0:
            raise ValueError(
                'current prefixlen is %d, cannot have a prefixlen_diff of %d' %
                (self.prefixlen, prefixlen_diff))
        return IPNetwork('%s/%s' % (str(self.network),
                                    str(self.prefixlen - prefixlen_diff)),
                         version=self._version)

    # backwards compatibility
    Subnet = subnet
    Supernet = supernet
    AddressExclude = address_exclude
    CompareNetworks = compare_networks
    Contains = __contains__


class _BaseV4(object):

    """Base IPv4 object.

    The following methods are used by IPv4 objects in both single IP
    addresses and networks.

    """

    # Equivalent to 255.255.255.255 or 32 bits of 1's.
    _ALL_ONES = (2**IPV4LENGTH) - 1
    _DECIMAL_DIGITS = frozenset('0123456789')

    def __init__(self, address):
        self._version = 4
        self._max_prefixlen = IPV4LENGTH

    def _explode_shorthand_ip_string(self):
        return str(self)

    def _ip_int_from_string(self, ip_str):
        """Turn the given IP string into an integer for comparison.

        Args:
            ip_str: A string, the IP ip_str.

        Returns:
            The IP ip_str as an integer.

        Raises:
            AddressValueError: if ip_str isn't a valid IPv4 Address.

        """
        octets = ip_str.split('.')
        if len(octets) != 4:
            raise AddressValueError(ip_str)

        packed_ip = 0
        for oc in octets:
            try:
                packed_ip = (packed_ip << 8) | self._parse_octet(oc)
            except ValueError:
                raise AddressValueError(ip_str)
        return packed_ip

    def _parse_octet(self, octet_str):
        """Convert a decimal octet into an integer.

        Args:
            octet_str: A string, the number to parse.

        Returns:
            The octet as an integer.

        Raises:
            ValueError: if the octet isn't strictly a decimal from [0..255].

        """
        # Whitelist the characters, since int() allows a lot of bizarre stuff.
        if not self._DECIMAL_DIGITS.issuperset(octet_str):
            raise ValueError
        octet_int = int(octet_str, 10)
        # Disallow leading zeroes, because no clear standard exists on
        # whether these should be interpreted as decimal or octal.
        if octet_int > 255 or (octet_str[0] == '0' and len(octet_str) > 1):
            raise ValueError
        return octet_int

    def _string_from_ip_int(self, ip_int):
        """Turns a 32-bit integer into dotted decimal notation.

        Args:
            ip_int: An integer, the IP address.

        Returns:
            The IP address as a string in dotted decimal notation.

        """
        octets = []
        for _ in xrange(4):
            octets.insert(0, str(ip_int & 0xFF))
            ip_int >>= 8
        return '.'.join(octets)

    @property
    def max_prefixlen(self):
        return self._max_prefixlen

    @property
    def packed(self):
        """The binary representation of this address."""
        return v4_int_to_packed(self._ip)

    @property
    def version(self):
        return self._version

    @property
    def is_reserved(self):
       """Test if the address is otherwise IETF reserved.

        Returns:
            A boolean, True if the address is within the
            reserved IPv4 Network range.

       """
       return self in IPv4Network('240.0.0.0/4')

    @property
    def is_private(self):
        """Test if this address is allocated for private networks.

        Returns:
            A boolean, True if the address is reserved per RFC 1918.

        """
        return (self in IPv4Network('10.0.0.0/8') or
                self in IPv4Network('172.16.0.0/12') or
                self in IPv4Network('192.168.0.0/16'))

    @property
    def is_multicast(self):
        """Test if the address is reserved for multicast use.

        Returns:
            A boolean, True if the address is multicast.
            See RFC 3171 for details.

        """
        return self in IPv4Network('224.0.0.0/4')

    @property
    def is_unspecified(self):
        """Test if the address is unspecified.

        Returns:
            A boolean, True if this is the unspecified address as defined in
            RFC 5735 3.

        """
        return self in IPv4Network('0.0.0.0')

    @property
    def is_loopback(self):
        """Test if the address is a loopback address.

        Returns:
            A boolean, True if the address is a loopback per RFC 3330.

        """
        return self in IPv4Network('127.0.0.0/8')

    @property
    def is_link_local(self):
        """Test if the address is reserved for link-local.

        Returns:
            A boolean, True if the address is link-local per RFC 3927.

        """
        return self in IPv4Network('169.254.0.0/16')


class Bytes(str):
    def __repr__(self):
        return 'Bytes(%s)' % str.__repr__(self)


class IPv4Address(_BaseV4, _BaseIP):

    """Represent and manipulate single IPv4 Addresses."""

    def __init__(self, address):

        _BaseV4.__init__(self, address)

        # Efficient copy constructor.
        if isinstance(address, IPv4Address):
            self._ip = address._ip
            return

        # Efficient constructor from integer.
        if isinstance(address, (int, long)):
            self._ip = address
            if address < 0 or address > self._ALL_ONES:
                raise AddressValueError(address)
            return

        # Constructing from a packed address
        if isinstance(address, Bytes):
            try:
                self._ip, = struct.unpack('!I', address)
            except struct.error:
                raise AddressValueError(address)  # Wrong length.
            return

        # Assume input argument to be string or any object representation
        # which converts into a formatted IP string.
        addr_str = str(address)
        self._ip = self._ip_int_from_string(addr_str)

class _BaseV6(object):

    """Base IPv6 object.

    The following methods are used by IPv6 objects in both single IP
    addresses and networks.

    """

    _ALL_ONES = (2**IPV6LENGTH) - 1
    _HEXTET_COUNT = 8
    _HEX_DIGITS = frozenset('0123456789ABCDEFabcdef')

    def __init__(self, address):
        self._version = 6
        self._max_prefixlen = IPV6LENGTH

    def _ip_int_from_string(self, ip_str):
        """Turn an IPv6 ip_str into an integer.

        Args:
            ip_str: A string, the IPv6 ip_str.

        Returns:
            A long, the IPv6 ip_str.

        Raises:
            AddressValueError: if ip_str isn't a valid IPv6 Address.

        """
        parts = ip_str.split(':')

        # An IPv6 address needs at least 2 colons (3 parts).
        if len(parts) < 3:
            raise AddressValueError(ip_str)

        # If the address has an IPv4-style suffix, convert it to hexadecimal.
        if '.' in parts[-1]:
            ipv4_int = IPv4Address(parts.pop())._ip
            parts.append('%x' % ((ipv4_int >> 16) & 0xFFFF))
            parts.append('%x' % (ipv4_int & 0xFFFF))

        # An IPv6 address can't have more than 8 colons (9 parts).
        if len(parts) > self._HEXTET_COUNT + 1:
            raise AddressValueError(ip_str)

        # Disregarding the endpoints, find '::' with nothing in between.
        # This indicates that a run of zeroes has been skipped.
        try:
            skip_index, = (
                [i for i in xrange(1, len(parts) - 1) if not parts[i]] or
                [None])
        except ValueError:
            # Can't have more than one '::'
            raise AddressValueError(ip_str)

        # parts_hi is the number of parts to copy from above/before the '::'
        # parts_lo is the number of parts to copy from below/after the '::'
        if skip_index is not None:
            # If we found a '::', then check if it also covers the endpoints.
            parts_hi = skip_index
            parts_lo = len(parts) - skip_index - 1
            if not parts[0]:
                parts_hi -= 1
                if parts_hi:
                    raise AddressValueError(ip_str)  # ^: requires ^::
            if not parts[-1]:
                parts_lo -= 1
                if parts_lo:
                    raise AddressValueError(ip_str)  # :$ requires ::$
            parts_skipped = self._HEXTET_COUNT - (parts_hi + parts_lo)
            if parts_skipped < 1:
                raise AddressValueError(ip_str)
        else:
            # Otherwise, allocate the entire address to parts_hi.  The endpoints
            # could still be empty, but _parse_hextet() will check for that.
            if len(parts) != self._HEXTET_COUNT:
                raise AddressValueError(ip_str)
            parts_hi = len(parts)
            parts_lo = 0
            parts_skipped = 0

        try:
            # Now, parse the hextets into a 128-bit integer.
            ip_int = 0L
            for i in xrange(parts_hi):
                ip_int <<= 16
                ip_int |= self._parse_hextet(parts[i])
            ip_int <<= 16 * parts_skipped
            for i in xrange(-parts_lo, 0):
                ip_int <<= 16
                ip_int |= self._parse_hextet(parts[i])
            return ip_int
        except ValueError:
            raise AddressValueError(ip_str)

    def _parse_hextet(self, hextet_str):
        """Convert an IPv6 hextet string into an integer.

        Args:
            hextet_str: A string, the number to parse.

        Returns:
            The hextet as an integer.

        Raises:
            ValueError: if the input isn't strictly a hex number from [0..FFFF].

        """
        # Whitelist the characters, since int() allows a lot of bizarre stuff.
        if not self._HEX_DIGITS.issuperset(hextet_str):
            raise ValueError
        if len(hextet_str) > 4:
          raise ValueError
        hextet_int = int(hextet_str, 16)
        if hextet_int > 0xFFFF:
            raise ValueError
        return hextet_int

    def _compress_hextets(self, hextets):
        """Compresses a list of hextets.

        Compresses a list of strings, replacing the longest continuous
        sequence of "0" in the list with "" and adding empty strings at
        the beginning or at the end of the string such that subsequently
        calling ":".join(hextets) will produce the compressed version of
        the IPv6 address.

        Args:
            hextets: A list of strings, the hextets to compress.

        Returns:
            A list of strings.

        """
        best_doublecolon_start = -1
        best_doublecolon_len = 0
        doublecolon_start = -1
        doublecolon_len = 0
        for index in range(len(hextets)):
            if hextets[index] == '0':
                doublecolon_len += 1
                if doublecolon_start == -1:
                    # Start of a sequence of zeros.
                    doublecolon_start = index
                if doublecolon_len > best_doublecolon_len:
                    # This is the longest sequence of zeros so far.
                    best_doublecolon_len = doublecolon_len
                    best_doublecolon_start = doublecolon_start
            else:
                doublecolon_len = 0
                doublecolon_start = -1

        if best_doublecolon_len > 1:
            best_doublecolon_end = (best_doublecolon_start +
                                    best_doublecolon_len)
            # For zeros at the end of the address.
            if best_doublecolon_end == len(hextets):
                hextets += ['']
            hextets[best_doublecolon_start:best_doublecolon_end] = ['']
            # For zeros at the beginning of the address.
            if best_doublecolon_start == 0:
                hextets = [''] + hextets

        return hextets

    def _string_from_ip_int(self, ip_int=None):
        """Turns a 128-bit integer into hexadecimal notation.

        Args:
            ip_int: An integer, the IP address.

        Returns:
            A string, the hexadecimal representation of the address.

        Raises:
            ValueError: The address is bigger than 128 bits of all ones.

        """
        if not ip_int and ip_int != 0:
            ip_int = int(self._ip)

        if ip_int > self._ALL_ONES:
            raise ValueError('IPv6 address is too large')

        hex_str = '%032x' % ip_int
        hextets = []
        for x in range(0, 32, 4):
            hextets.append('%x' % int(hex_str[x:x+4], 16))

        hextets = self._compress_hextets(hextets)
        return ':'.join(hextets)

    def _explode_shorthand_ip_string(self):
        """Expand a shortened IPv6 address.

        Args:
            ip_str: A string, the IPv6 address.

        Returns:
            A string, the expanded IPv6 address.

        """
        if isinstance(self, _BaseNet):
            ip_str = str(self.ip)
        else:
            ip_str = str(self)

        ip_int = self._ip_int_from_string(ip_str)
        parts = []
        for i in xrange(self._HEXTET_COUNT):
            parts.append('%04x' % (ip_int & 0xFFFF))
            ip_int >>= 16
        parts.reverse()
        if isinstance(self, _BaseNet):
            return '%s/%d' % (':'.join(parts), self.prefixlen)
        return ':'.join(parts)

    @property
    def max_prefixlen(self):
        return self._max_prefixlen

    @property
    def packed(self):
        """The binary representation of this address."""
        return v6_int_to_packed(self._ip)

    @property
    def version(self):
        return self._version

    @property
    def is_multicast(self):
        """Test if the address is reserved for multicast use.

        Returns:
            A boolean, True if the address is a multicast address.
            See RFC 2373 2.7 for details.

        """
        return self in IPv6Network('ff00::/8')

    @property
    def is_reserved(self):
        """Test if the address is otherwise IETF reserved.

        Returns:
            A boolean, True if the address is within one of the
            reserved IPv6 Network ranges.

        """
        return (self in IPv6Network('::/8') or
                self in IPv6Network('100::/8') or
                self in IPv6Network('200::/7') or
                self in IPv6Network('400::/6') or
                self in IPv6Network('800::/5') or
                self in IPv6Network('1000::/4') or
                self in IPv6Network('4000::/3') or
                self in IPv6Network('6000::/3') or
                self in IPv6Network('8000::/3') or
                self in IPv6Network('A000::/3') or
                self in IPv6Network('C000::/3') or
                self in IPv6Network('E000::/4') or
                self in IPv6Network('F000::/5') or
                self in IPv6Network('F800::/6') or
                self in IPv6Network('FE00::/9'))

    @property
    def is_unspecified(self):
        """Test if the address is unspecified.

        Returns:
            A boolean, True if this is the unspecified address as defined in
            RFC 2373 2.5.2.

        """
        return self._ip == 0 and getattr(self, '_prefixlen', 128) == 128

    @property
    def is_loopback(self):
        """Test if the address is a loopback address.

        Returns:
            A boolean, True if the address is a loopback address as defined in
            RFC 2373 2.5.3.

        """
        return self._ip == 1 and getattr(self, '_prefixlen', 128) == 128

    @property
    def is_link_local(self):
        """Test if the address is reserved for link-local.

        Returns:
            A boolean, True if the address is reserved per RFC 4291.

        """
        return self in IPv6Network('fe80::/10')

    @property
    def is_site_local(self):
        """Test if the address is reserved for site-local.

        Note that the site-local address space has been deprecated by RFC 3879.
        Use is_private to test if this address is in the space of unique local
        addresses as defined by RFC 4193.

        Returns:
            A boolean, True if the address is reserved per RFC 3513 2.5.6.

        """
        return self in IPv6Network('fec0::/10')

    @property
    def is_private(self):
        """Test if this address is allocated for private networks.

        Returns:
            A boolean, True if the address is reserved per RFC 4193.

        """
        return self in IPv6Network('fc00::/7')

    @property
    def ipv4_mapped(self):
        """Return the IPv4 mapped address.

        Returns:
            If the IPv6 address is a v4 mapped address, return the
            IPv4 mapped address. Return None otherwise.

        """
        if (self._ip >> 32) != 0xFFFF:
            return None
        return IPv4Address(self._ip & 0xFFFFFFFF)

    @property
    def teredo(self):
        """Tuple of embedded teredo IPs.

        Returns:
            Tuple of the (server, client) IPs or None if the address
            doesn't appear to be a teredo address (doesn't start with
            2001::/32)

        """
        if (self._ip >> 96) != 0x20010000:
            return None
        return (IPv4Address((self._ip >> 64) & 0xFFFFFFFF),
                IPv4Address(~self._ip & 0xFFFFFFFF))

    @property
    def sixtofour(self):
        """Return the IPv4 6to4 embedded address.

        Returns:
            The IPv4 6to4-embedded address if present or None if the
            address doesn't appear to contain a 6to4 embedded address.

        """
        if (self._ip >> 112) != 0x2002:
            return None
        return IPv4Address((self._ip >> 80) & 0xFFFFFFFF)




class IPv6Address(_BaseV6, _BaseIP):

    """Represent and manipulate single IPv6 Addresses.
    """

    def __init__(self, address):

        _BaseV6.__init__(self, address)

        # Efficient copy constructor.
        if isinstance(address, IPv6Address):
            self._ip = address._ip
            return

        # Efficient constructor from integer.
        if isinstance(address, (int, long)):
            self._ip = address
            if address < 0 or address > self._ALL_ONES:
                raise AddressValueError(address)
            return

        # Constructing from a packed address
        if isinstance(address, Bytes):
            try:
                hi, lo = struct.unpack('!QQ', address)
            except struct.error:
                raise AddressValueError(address)  # Wrong length.
            self._ip = (hi << 64) | lo
            return

        # Assume input argument to be string or any object representation
        # which converts into a formatted IP string.
        addr_str = str(address)
        self._ip = self._ip_int_from_string(addr_str)


def IPAddress(address, version=None):

    if version:
        if version == 4:
            return IPv4Address(address)
        elif version == 6:
            return IPv6Address(address)
    try:
        return IPv4Address(address)
    except (AddressValueError, NetmaskValueError):
        pass

    try:
        return IPv6Address(address)
    except (AddressValueError, NetmaskValueError):
        pass

    #raise ValueError('%r does not appear to be an IPv4 or IPv6 address' % address)
    return 1

''' *********************************************************************************************************** '''

def list_of_ports(list):

    ports = []

    for x in list:

        if '-' in x:
            x = x.split('-')
            if x[0].isalpha() or x[1].isalpha():
                return 1
            if int(x[0]) < 0 or int(x[1]) > 65535:
                return 1
            for i in range(int(x[0]),int(x[1])+1):
                ports.append(i)
        else:
            if x.isalpha():
                return 1
            if int(x) < 0 or int(x) > 65535:
                return 1
            ports.append(int(x))

    return ports

def is_there_conflict(list1, list2):

    if len(list1) > 0 and len(list2) > 0:
        ignore = list1.split(',')
        hot = list2.split(',')

        ports_to_ignore = list_of_ports(ignore) 

        if ports_to_ignore == 1:
            return 1        
        
        hot_list = list_of_ports(hot)
        if hot_list == 1:
            return 1

        for port in ports_to_ignore:
            if port in hot_list:
                return 1
    
    return 0

def get_current_config():
    
    try:
        config_file = os.environ["GARGOYLE_CONFIG"]
    except KeyError:
        config_file = '.gargoyle_config'

    file = open(config_file, 'r')
    lines = file.read().splitlines()
      
    cur = {}
    for x in lines:
        key_val = x.split(':')
        if len(key_val) > 1:
            if  ',' in key_val[1] or '-' in key_val[1]:
                cur[key_val[0]] = key_val[1]
            else:
                cur[key_val[0]] = int(key_val[1])
    file.close()

    return json.dumps(cur)
    
def set_config(objct):

    ''' dictionary of user specified key-values from gui '''
    data = json.loads(objct)
    
    try:
        config_file = os.environ["GARGOYLE_CONFIG"]
    except KeyError:
        config_file = '.gargoyle_config'
  
    temp = get_current_config()
    current = json.loads(temp)
    if 'ports_to_ignore' and 'hot_ports' in data.keys():
        if is_there_conflict(data['ports_to_ignore'],data['hot_ports']):
            return 1

    for key in data:

        if key == 'enforce':
            if int(data[key]) != 1 and int(data[key]) != 0:
                return 1

        data[key] = str(data[key])

        if data[key].isalpha():
            return 1    

        if key not in current.keys():
            current[key] = data[key]
        elif data[key] != current[key]:      
            current[key] = data[key]

    file = open(config_file,'w')

    for key in current:
        if key in data.keys():
            file.write(key)
            file.write(':')
            file.write(str(current[key]))
            file.write('\n')
    file.close()
        
    return 0

def unblock_ip(ip_addr='',version=None):

    ip_address = IPAddress(ip_addr)   
    if ip_address == 1:
        return 1
    black_list_ix = None
    host_ix = None
    db_loc = get_db()

    try:
        table = sqlite3.connect(db_loc)    
        cursor = table.cursor()
    except sqlite3.Error as e:
        print(e)
                
    try:
        with table:
            cursor.execute("SELECT ix FROM hosts_table WHERE host = '{}'".format(ip_addr))
            host_ix = cursor.fetchone()[0]

    except TypeError:
        pass

    if host_ix:
        ''' using the ip addr ix we talk to black_ip_list table '''
        try:
            with table:   
                cursor.execute("SELECT ix FROM black_ip_list WHERE host_ix = '{}'".format(host_ix))
                black_list_ix = cursor.fetchone()[0]
        except TypeError:
            pass

    if black_list_ix:
            return 2

    ''' 
    This works from any directory that has the 
    gargoyle_pscand_unblockip executable as long 
    as the correct GARGOYLE_DB environment variable is set
    '''

    cmd = ['sudo', 'su', '-c', 'gargoyle_pscand_unblockip {}'.format(ip_addr)]
    call(cmd)

    return 0

def get_db():
    
    #DB_PATH = "/db/port_scan_detect.db"
    DB_PATH = "/db/gargoyle_attack_detect.db"
    db_file = None
        
    try:
        db_file = os.environ["GARGOYLE_DB"]

    except KeyError:
        pass
               
    if not db_file:
        cur_dir = os.getcwd()
        db_loc = cur_dir + DB_PATH
    else:
        db_loc = db_file

    return db_loc

def get_current_white_list():

    db_loc = get_db()
    host_ix_list = {}
    white_listed_ips = {}

    try:
        table = sqlite3.connect(db_loc)
        cursor = table.cursor()
    except sqlite3.Error as e:
        print(e)

    try:
        with table:
            cursor.execute("SELECT * FROM ignore_ip_list")
            white_listed_entries = cursor.fetchall()
    except TypeError:
        pass

    for entry in white_listed_entries:
        host_ix_list[entry[1]] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(entry[2])))

    for host_ix in host_ix_list.keys():
        with table:
            try:
                cursor.execute("SELECT * FROM hosts_table where ix={}".format(host_ix))
                val = cursor.fetchall()
                if val != []:
                    host = val[0]
                    white_listed_ips[host[1]] = host_ix_list[host_ix]
            except TypeError:
                pass

    return white_listed_ips
    
'''query detected_hosts, if it exists, call unblock then add a row to white list table. if not, just add row to white list'''
def add_to_white_list(ip_addr=''):

    ip_address = IPAddress(ip_addr)
    if ip_address == 1:
        return 1
    
    host_ix = None
    detected_host_ix = None
    black_list_ix = None
    val = None
    db_loc = get_db()

    try:
        table = sqlite3.connect(db_loc)    
        cursor = table.cursor()
    except sqlite3.Error as e:
        print(e)
                
    '''
    	have to get the ip addr ix first
    	
    	if it exists need to update last_seen to 63072000 so that
    	the clean up process does not delete the ip addr from the
    	hosts_table
    	
    	63072000 = 01/01/1972 @ 12:00am (UTC)
    '''
    try:
        with table:
            cursor.execute("SELECT ix FROM hosts_table WHERE host = '{}'".format(ip_addr))
            host_ix = cursor.fetchone()[0]
            cursor.execute("UPDATE hosts_table SET last_seen = 63072000 WHERE ix = {}".format(host_ix))

    except TypeError:
        ''' insert into hosts_table first '''
        tstamp = int(time.mktime(time.localtime()))
        with table:
            cursor.execute("INSERT INTO hosts_table (host, first_seen, last_seen) VALUES (?,?,?)",(ip_addr, tstamp, 63072000))
            cursor.execute("SELECT ix FROM hosts_table WHERE host = '{}'".format(ip_addr))
            host_ix = cursor.fetchone()[0]
            
        
    if host_ix:
        ''' using the ip addr ix we talk to detected_hosts table '''
        try:
            with table:   
                cursor.execute("SELECT ix FROM detected_hosts WHERE host_ix = '{}'".format(host_ix))
                detected_host_ix = cursor.fetchone()[0]

        except TypeError:
            pass
    
        ''' using the ip addr ix we talk to black_ip_list table '''
        try:
            with table:   
                cursor.execute("SELECT ix FROM black_ip_list WHERE host_ix = '{}'".format(host_ix))
                black_list_ix = cursor.fetchone()[0]
        except TypeError:
            pass

        if black_list_ix:
            ''' exists in black_ip_list so we remove '''
            remove_from_black_list(ip_addr)

        ''' exists actively in iptables '''
        if detected_host_ix:
            '''
                note that the unblock program performs
                the insert into ignore_ip_list
            '''
            unblock_ip(ip_addr = ip_addr)

        else: 
            with table:
                cursor.execute("SELECT * FROM ignore_ip_list where host_ix = '{}'".format(host_ix))
                val = cursor.fetchone()
                if val:
                    tstamp = val[2]

            if val == None:   
    
                ''' not in white list so insert '''
                
                with table:
                    tstamp = int(time.mktime(time.localtime()))
                    cursor.execute("INSERT INTO ignore_ip_list (host_ix, timestamp) VALUES ({},{})".format(host_ix, tstamp))

    syslog.openlog("gargoyle_pscand")
    syslog.syslog('action="add to whitelist" violator="%s" timestamp="%d"'% (ip_addr,tstamp))

    return 0

def remove_from_white_list(ip_addr=''):

    ip_address = IPAddress(ip_addr)
    if ip_address == 1:
        return 1

    cmd = ['sudo', 'su', '-c', 'gargoyle_pscand_remove_from_whitelist {}'.format(ip_addr)]
    call(cmd)
    
    tstamp = int(time.mktime(time.localtime()))
    syslog.openlog("gargoyle_pscand")
    syslog.syslog('action="remove from whitelist" violator="%s" timestamp="%d"'% (ip_addr,tstamp))

    return 0

def get_current_black_list():

    db_loc = get_db()
    host_ix_list = {}
    black_listed_ips = {}

    try:
        table = sqlite3.connect(db_loc)
        cursor = table.cursor()
    except sqlite3.Error as e:
        print(e)

    try:
        with table:
            cursor.execute("SELECT * FROM black_ip_list")
            black_listed_entries = cursor.fetchall()
    except TypeError:
        pass

    for entry in black_listed_entries:
        host_ix_list[entry[1]] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(entry[2])))

    for host_ix in host_ix_list.keys():
        with table:
            try:
                cursor.execute("SELECT * FROM hosts_table where ix={}".format(host_ix))
                val = cursor.fetchall()
                if val != []:
                    host = val[0]
                    black_listed_ips[host[1]] = host_ix_list[host_ix]
            except TypeError:
                pass

    return black_listed_ips

'''query detected_hosts, if it exists, call unblock then add a row to black list table. if not, just add row to black list'''
def add_to_black_list(ip_addr=''):

    ip_address = IPAddress(ip_addr)
    if ip_address == 1:
        return 1
    
    host_ix = None
    detected_host_ix = None
    white_list_ix = None
    val = None
    db_loc = get_db()
    
    try:
        table = sqlite3.connect(db_loc)
        cursor = table.cursor()
    except sqlite3.Error as e:
        print(e)
                
    '''
    	have to get the ip addr ix first
    	
    	if it exists need to update last_seen to 63072000 so that
    	the clean up process does not delete the ip addr from the
    	hosts_table
    	
    	63072000 = 01/01/1972 @ 12:00am (UTC)
    '''
    try:
        with table:
            cursor.execute("SELECT ix FROM hosts_table WHERE host = '{}'".format(ip_addr))
            host_ix = cursor.fetchone()[0]
            cursor.execute("UPDATE hosts_table SET last_seen = 63072000 WHERE ix = {}".format(host_ix))

    except TypeError:
        ''' insert into hosts_table first '''
        tstamp = int(time.mktime(time.localtime()))
        with table:
            cursor.execute("INSERT INTO hosts_table (host, first_seen, last_seen) VALUES (?,?,?)",(ip_addr, tstamp, 63072000))
            cursor.execute("SELECT ix FROM hosts_table WHERE host = '{}'".format(ip_addr))
            host_ix = cursor.fetchone()[0]
            
        
    if host_ix:
        ''' using the ip addr ix we talk to detected_hosts table '''
        try:
            with table:   
                cursor.execute("SELECT ix FROM detected_hosts WHERE host_ix = '{}'".format(host_ix))
                detected_host_ix = cursor.fetchone()[0]

        except TypeError:
            pass
    
        ''' exists actively in detected_hosts '''
        if detected_host_ix:

            unblock_ip(ip_addr = ip_addr)

        try:
            with table:
                cursor.execute("SELECT ix FROM ignore_ip_list WHERE host_ix = '{}'".format(host_ix))
                white_list_ix = cursor.fetchone()[0]

        except TypeError:
            pass

        if white_list_ix:
            ''' exists in ignore_ip_list so we delete '''
            remove_from_white_list(ip_addr)
 
        with table:
            cursor.execute("SELECT * FROM black_ip_list where host_ix = '{}'".format(host_ix))
            val = cursor.fetchone()
            if val:
                tstamp = val[2]
        if val == None:   
    
            ''' not in black list so insert '''
                
            with table:
                tstamp = int(time.mktime(time.localtime()))
                cursor.execute("INSERT INTO black_ip_list (host_ix, timestamp) VALUES ({},{})".format(host_ix, tstamp))

    syslog.openlog("gargoyle_pscand")
    syslog.syslog('action="add to blacklist" violator="%s" timestamp="%d"'% (ip_addr,tstamp))

    return 0

def remove_from_black_list(ip_addr=''):

    ip_address = IPAddress(ip_addr)
    if ip_address == 1:
        return 1
    
    cmd = ['sudo', 'su', '-c', 'gargoyle_pscand_remove_from_blacklist {}'.format(ip_addr)]
    call(cmd)
    
    tstamp = int(time.mktime(time.localtime()))
    syslog.openlog("gargoyle_pscand")
    syslog.syslog('action="remove from blacklist" violator="%s" timestamp="%d"'% (ip_addr,tstamp))

    return 0

'''
returns list of string of ips in iptables
'''   
def get_current_from_iptables():
    
    ips_in_iptables = []
    blocked_ips = {}
    first_seen = 0
    last_seen = 0

    cmd = ['sudo iptables -L GARGOYLE_Input_Chain -n']
    p = Popen(cmd, stdout=PIPE, shell=True)
    out,err = p.communicate()
    
    
    lines = out.split('\n')
    for line in lines:
        if len(line) > 0:
            each_line = line.split()
            if each_line[0] == 'DROP':
                ips_in_iptables.append(each_line[3])
    
    host_ix = None
    db_loc = get_db()
    
    try:
        table = sqlite3.connect(db_loc)
        cursor = table.cursor()
    except sqlite3.Error as e:
        print(e)

    for ip in ips_in_iptables:
        try:
            with table:
                cursor.execute("SELECT first_seen FROM hosts_table WHERE host = '{}'".format(ip))
                first_seen = cursor.fetchone()[0]
        except TypeError:
            pass

        try:
            with table:
                cursor.execute("SELECT last_seen FROM hosts_table WHERE host = '{}'".format(ip))
                last_seen = cursor.fetchone()[0]
        except TypeError:
            pass

        blocked_ips[ip] = [first_seen,last_seen]
        
    return blocked_ips

def blocked_time():

    blocked_timestamps = {}
    blocked_ips = get_current_from_iptables()
    host_ix = None
    db_loc = get_db()
    blocked_time = None
    daemons = daemon_stats()
    last_monitor_run = daemons['last_monitor']
    next_monitor_run = int(datetime.strptime(daemons['next_monitor'], "%Y-%m-%d %H:%M:%S").strftime("%s"))
    lockout_time = json.loads(get_current_config())['lockout_time']

    try:
        table = sqlite3.connect(db_loc)
        cursor = table.cursor()
    except sqlite3.Error as e:
        print(e)

    for ip in blocked_ips.keys():
        host_ix = None
        try:
            with table:
                cursor.execute("SELECT ix FROM hosts_table WHERE host = '{}'".format(ip))
                host_ix = cursor.fetchone()[0]

        except TypeError:
            pass
    

        if host_ix:
            try:
                with table:
                    cursor.execute("SELECT timestamp FROM detected_hosts WHERE host_ix = '{}'".format(host_ix))
                    blocked_time = cursor.fetchone()[0]

            except TypeError:
                pass
    
        if blocked_time:
            blocked_time = int(blocked_time)
            started = daemons['Active']
            date = re.search('(\d{4}\-(\d{2}(\-|\s)){2})(\d{2}:*){3}',started)
            if date:
                strdate = date.group(0)
                datetm = datetime.strptime(strdate,"%Y-%m-%d %H:%M:%S")
                startseconds = datetm.strftime("%s")
            
            if ip in get_current_black_list().keys():
                blocked_timestamps[ip] = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(blocked_time)) , 0]
            elif blocked_time + lockout_time <= next_monitor_run:
                blocked_timestamps[ip] = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(blocked_time)) , time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_monitor_run))]
            else:
                while((blocked_time + lockout_time) > next_monitor_run):
                    next_monitor_run += 43200
                blocked_timestamps[ip] = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(blocked_time)) , time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_monitor_run))]
                
    return blocked_timestamps

def daemon_stats():

    daemon = {}
    cmd = ['service gargoyle_pscand status']
    p = Popen (cmd, stdout=PIPE, shell=True)
    out, err = p.communicate()
    
    splitOut = out.split('\n')

    for x in splitOut:
        if 'Active' in x:
            daemon['Active'] = x.strip()
        '''
        if re.match("[\w]{3}\s([\d]{2}(:|\s)){4}(\w|\W)+gargoyle_pscand_[\w]+", x):
            if 'Timeline' not in daemon.keys():
                daemon['Timeline'] = []
            daemon['Timeline'].append(x.strip())
            '''
        if './gargoyle_' in x:
            if 'runningDaemons' not in daemon.keys():
                daemon['runningDaemons'] = []
            daemon['runningDaemons'].append(x.strip().decode("utf-8").encode("ascii","ignore").split()[1])

    if 'running' in daemon['Active']:
        try:
            last_analysis = int(subprocess.check_output(["cat /var/log/syslog | grep  'analysis process commencing at'"], shell=True).split()[-1])
            next_analysis = last_analysis + 900
        except:
            time_str = re.search("((\d{4}\-\d{2}\-)(\d{2}(:|\s)){4})", daemon['Active']).group(1)
            time_converted = datetime.strptime(time_str.rstrip(),"%Y-%m-%d %H:%M:%S")
            last_analysis = int(time_converted.strftime("%s"))
            next_analysis = last_analysis + 900
            
        try:
            last_monitor = int(subprocess.check_output(["cat /var/log/syslog | grep  'monitor process commencing at'"], shell=True).split()[-1])
            next_monitor = last_monitor + 43200
        except:
            time_str = re.search("((\d{4}\-\d{2}\-)(\d{2}(:|\s)){4})", daemon['Active']).group(1)
            time_converted = datetime.strptime(time_str.rstrip(),"%Y-%m-%d %H:%M:%S")
            last_monitor = int(time_converted.strftime("%s"))
            next_monitor = last_monitor + 43200
                           
        current_time = int(time.mktime(time.localtime()))
        while next_monitor < current_time:
            next_monitor += 43200
        while next_analysis < current_time:
            next_analysis += 900

        daemon["last_monitor"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_monitor))
        daemon["last_analysis"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_analysis))
        daemon["next_monitor"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_monitor))
        daemon["next_analysis"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_analysis))

    return daemon


