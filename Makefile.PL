use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
  'NAME'  => 'Win32::PingICMP',
  'VERSION_FROM' => 'Win32/PingICMP.pm', # finds $VERSION
  'PM' => {
    'Win32/PingICMP.pm' =>                  '$(INST_LIBDIR)/PingICMP.pm',
  },
  'PREREQ_PM' => {
    'Win32::API' => '0', # or a minimum workable version
  },
  'AUTHOR' => 'Toby Everett',
  'ABSTRACT' => 'ICMP Ping support for Win32 platforms based on ICMP.DLL',
);



