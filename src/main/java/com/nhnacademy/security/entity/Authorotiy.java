package com.nhnacademy.security.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name="Authoroties")
public class Authorotiy {

    @Id
    @Column(name = "member_id")
    private String memberId;

    @MapsId("memberId")
    @OneToOne
    @JoinColumn(name = "member_id")
    private Member member;

    @Column(name = "authority")
    private String authority;

}
