![[Pasted image 20250913210337.png]]

이러한 계기로 Page UAF를 분석하기로 결심했다. 자료가 다 영어라서 영어로 정리를 하는 것이 더 쉽지만 이해를 잘 했다면 한국어로도 쓸 수 있겠지 싶어 한국어로 정리하겠다.

목차 ???
# Page UAF는 왜 발생할까

첫 번째는 Page Table(이하 PT)를 직접 손상시켰을 때이다. PT도 커널 데이터이므로 커널 메모리 손상 취약점으로 PT를 조작하면 된다.
두 번째는 커널의 Dangling page mapping 취약점이 발생할 때이다. Virtual Address(이하 VA) 1과 VA2가 같은 Physical Address(이하 PA)를 가리킨 상태에서 VA2를 munmap시키면, 커널에서는 그 PA가 해제된 상태라고 생각하고 이를 사용하므로 VA1이 댕글링 포인터가 된다. 커널이 해당 PA를 사용하면 VA1을 이용하여 중요한 정보를 읽어올 수 있다.
Dangling page mapping 취약점은 왜 발생할까? 여러 가지 원인이 있는데, 우선 Dangling Address Translation Entry(이하 ATE)가 있다. ATE는 CPU나 MMU에서 VA -> PA 매핑 정보를 담는 엔트리이다. OS 커널, 드라이버, 혹은 IOMMU가 특정 매핑을 해제했는데도 그 매핑 엔트리가 여전히 남아 있으면 Dangling ATE가 된다. Dangling Page Table Entry(이하 PTE)가 있다. PTE는 가상 메모리 시스템에서 **페이지 테이블 항목**을 뜻한다.