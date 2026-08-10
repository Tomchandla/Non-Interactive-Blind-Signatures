catch2 = subproject('catch2')
catch2_with_main_dep = catch2.get_variable('catch2_with_main_dep')

test_sources = [
  'test_voleconsv_bs.cpp',
]
executable('tests',
  test_sources,
  dependencies : [catch2_with_main_dep, faest_dep]
)
