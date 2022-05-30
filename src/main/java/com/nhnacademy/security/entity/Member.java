package com.nhnacademy.security.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "Members")
public class Member {

    @Id
    @Column(name = "member_id")
    private String memberId;

    @Column(name = "name")
    private String name;

    @Column(name = "pwd")
    private String pw;
}
