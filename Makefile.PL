use 5.012004;
use ExtUtils::MakeMaker;
require ExtUtils::Liblist;


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Mail::DMARC::opendmarc',
    VERSION_FROM      => 'lib/Mail/DMARC/opendmarc.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Mail/DMARC/opendmarc.pm', # retrieve abstract from module
       AUTHOR         => 'Davide Migliavacca <shari@cpan.org>') : ()),
    LIBS              => ['-lresolv'], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I', # e.g., '-I. -I/usr/include/other'
	TYPEMAPS		  => ['typemap'],
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
	META_MERGE		  => {
				release_status => 'unstable',
				license =>  ['artistic_2']
				}
);
